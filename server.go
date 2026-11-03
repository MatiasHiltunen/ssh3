package ssh3

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

type ServerConversationHandler func(authenticatedUsername string, conversation *Conversation) error

type Server struct {
	maxPacketSize            uint64
	h3Server                 *http3.Server
	conversations            map[*quic.Conn]*conversationsManager
	conversationHandler      ServerConversationHandler
	lock                     sync.Mutex
	defaultDatagramQueueSize uint64
	listener                 *quic.EarlyListener
	connections              map[*quic.Conn]struct{}
	closed                   bool
	// conversations map[]
}

// Creates a new server handling http requests for SSH conversations

func NewServer(maxPacketSize uint64, defaultDatagramQueueSize uint64, h3Server *http3.Server, conversationHandler ServerConversationHandler) *Server {
	ssh3Server := &Server{
		maxPacketSize:            maxPacketSize,
		h3Server:                 h3Server,
		conversations:            make(map[*quic.Conn]*conversationsManager),
		connections:              make(map[*quic.Conn]struct{}),
		conversationHandler:      conversationHandler,
		defaultDatagramQueueSize: defaultDatagramQueueSize,
	}

	previousContext := h3Server.ConnContext
	h3Server.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
		if previousContext != nil {
			ctx = previousContext(ctx, conn)
		}
		return context.WithValue(ctx, quicConnectionKey{}, conn)
	}
	return ssh3Server
}

func (s *Server) acceptSSHChannel(qconn *quic.Conn, stream *quic.Stream) error {
	conversationsManager, ok := s.getConversationsManager(qconn)
	if !ok {
		err := fmt.Errorf("unauthenticated connection cannot open SSH3 channel %d", stream.StreamID())
		log.Error().Msgf("%s", err)
		return err
	}

	conversationControlStreamID, channelType, maxPacketSize, err := parseHeader(uint64(stream.StreamID()), &StreamByteReader{stream})
	if err != nil {
		return err
	}

	conversation, ok := conversationsManager.getConversation(conversationControlStreamID)
	if !ok {
		err := fmt.Errorf("could not find SSH3 conversation with control stream id %d for new channel %d", conversationControlStreamID,
			uint64(stream.StreamID()))
		log.Error().Msgf("%s", err)
		return err
	}
	log.Debug().Msgf(
		"accepted SSH3 channel %d of type %q for control stream %d",
		uint64(stream.StreamID()),
		channelType,
		conversationControlStreamID,
	)

	channelInfo := &ChannelInfo{
		ConversationID:       conversation.conversationID,
		ConversationStreamID: conversationControlStreamID,
		ChannelID:            uint64(stream.StreamID()),
		ChannelType:          channelType,
		MaxPacketSize:        maxPacketSize,
	}

	newChannel := NewChannel(channelInfo.ConversationStreamID, channelInfo.ConversationID, uint64(stream.StreamID()), channelInfo.ChannelType, channelInfo.MaxPacketSize, &StreamByteReader{stream},
		stream, nil, conversation.channelsManager, false, false, true, s.defaultDatagramQueueSize, nil)

	switch channelInfo.ChannelType {
	case "direct-udp":
		udpAddr, err := parseUDPForwardingHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			return err
		}
		newChannel.setDatagramSender(conversation.getDatagramSenderForChannel(channelInfo.ChannelID))
		newChannel = &UDPForwardingChannelImpl{Channel: newChannel, RemoteAddr: udpAddr}
	case "direct-tcp":
		tcpAddr, err := parseTCPForwardingHeader(channelInfo.ChannelID, &StreamByteReader{stream})
		if err != nil {
			return err
		}
		newChannel = &TCPForwardingChannelImpl{Channel: newChannel, RemoteAddr: tcpAddr}
	}
	conversation.channelsAcceptQueue.Add(newChannel)
	return nil
}

func (s *Server) getConversationsManager(streamCreator *quic.Conn) (*conversationsManager, bool) {
	s.lock.Lock()
	defer s.lock.Unlock()
	conversations, ok := s.conversations[streamCreator]
	return conversations, ok
}

func (s *Server) getOrCreateConversationsManager(streamCreator *quic.Conn) *conversationsManager {
	s.lock.Lock()
	defer s.lock.Unlock()
	conversationsManager, ok := s.conversations[streamCreator]
	if !ok {
		s.conversations[streamCreator] = newConversationManager(streamCreator)
		conversationsManager = s.conversations[streamCreator]
	}
	return conversationsManager
}

func (s *Server) removeConnection(streamCreator *quic.Conn) {
	s.lock.Lock()
	defer s.lock.Unlock()
	delete(s.conversations, streamCreator)
	delete(s.connections, streamCreator)
}

type AuthenticatedHandlerFunc func(authenticatedUserName string, newConv *Conversation, w http.ResponseWriter, r *http.Request)

type UnauthenticatedBearerFunc func(unauthenticatedBearerString string, base64ConversationID string, w http.ResponseWriter, r *http.Request)

func (s *Server) GetHTTPHandlerFunc(ctx context.Context) AuthenticatedHandlerFunc {

	return func(authenticatedUsername string, newConv *Conversation, w http.ResponseWriter, r *http.Request) {
		log.Info().Msgf("got request: method: %s, URL: %s", r.Method, r.URL.String())
		if r.Method == http.MethodConnect {
			if r.Proto != "ssh3" {
				log.Debug().Msgf("accepting CONNECT request with proto %q as SSH3", r.Proto)
			}
			qconn, ok := QUICConnectionFromRequest(r)
			streamer, streamOK := w.(http3.HTTPStreamer)
			if !ok || !streamOK {
				http.Error(w, "HTTP/3 connection unavailable", http.StatusInternalServerError)
				return
			}
			// Hijack only after authentication. HTTPStream flushes the success response.
			conversationsManager := s.getOrCreateConversationsManager(qconn)
			conversationsManager.lock.Lock()
			w.WriteHeader(http.StatusOK)
			newConv.controlStream = streamer.HTTPStream()
			conversationsManager.conversations[uint64(newConv.controlStream.StreamID())] = newConv
			conversationsManager.lock.Unlock()
			log.Debug().Msgf(
				"accepted SSH3 CONNECT for user %s on control stream %d",
				authenticatedUsername,
				newConv.controlStream.StreamID(),
			)

			go func() {
				defer newConv.Close()
				defer conversationsManager.removeConversation(newConv)
				if err := s.conversationHandler(authenticatedUsername, newConv); err != nil {
					if errors.Is(err, context.Canceled) {
						log.Info().Msgf("conversation canceled for conversation id %s, user %s", newConv.ConversationID(), authenticatedUsername)
					} else {
						log.Error().Msgf("error while handing new conversation: %s for user %s: %s", newConv.ConversationID(), authenticatedUsername, err)
					}
					return
				}
			}()
		}
	}
}
