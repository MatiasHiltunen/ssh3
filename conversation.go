package ssh3

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/francoismichel/ssh3/util"
	"slices"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

const SSH_FRAME_TYPE = 0xaf3627e6

type ConversationID [32]byte

func (cid ConversationID) String() string {
	return base64.StdEncoding.EncodeToString(cid[:])
}

type Conversation struct {
	controlStream             Stream
	maxPacketSize             uint64
	defaultDatagramsQueueSize uint64
	streamCreator             *quic.Conn
	messageSender             util.DatagramSender
	channelsManager           *channelsManager
	context                   context.Context
	cancelContext             context.CancelCauseFunc
	conversationID            ConversationID // generated using TLS exporters
	peerVersion               Version

	channelsAcceptQueue *util.AcceptQueue[Channel]
}

func GenerateConversationID(tls *tls.ConnectionState) (convID ConversationID, err error) {
	ret, err := tls.ExportKeyingMaterial("EXPORTER-SSH3", nil, 32)
	if err != nil {
		return convID, err
	}
	if len(ret) != len(convID) {
		return convID, fmt.Errorf("TLS returned a tls-exporter with the wrong length (%d instead of %d)", len(ret), len(convID))
	}
	copy(convID[:], ret)
	return convID, err
}

func NewClientConversation(maxPacketsize uint64, defaultDatagramsQueueSize uint64, tls *tls.ConnectionState) (*Conversation, error) {
	if err := validatePacketSize(maxPacketsize); err != nil {
		return nil, err
	}
	convID, err := GenerateConversationID(tls)
	if err != nil {
		log.Error().Msgf("could not generate conversation ID: %s", err)
		return nil, err
	}
	backgroundCtx, backgroundCancelCauseFunc := context.WithCancelCause(context.Background())
	conv := &Conversation{
		controlStream:             nil,
		channelsAcceptQueue:       util.NewAcceptQueue[Channel](),
		streamCreator:             nil,
		maxPacketSize:             maxPacketsize,
		defaultDatagramsQueueSize: defaultDatagramsQueueSize,
		channelsManager:           newChannelsManager(),
		context:                   backgroundCtx,
		cancelContext:             backgroundCancelCauseFunc,
		conversationID:            convID,

		// peerVersion set afterwards
	}
	return conv, nil
}

func (c *Conversation) EstablishClientConversation(req *http.Request, roundTripper *http3.Transport, qconn *quic.Conn, supportedVersions []Version) error {

	c.streamCreator = qconn
	c.messageSender = qconn
	c.context, c.cancelContext = context.WithCancelCause(qconn.Context())
	ready := make(chan struct{})
	established := false
	defer close(ready)
	raw := roundTripper.NewRawClientConn(qconn)
	raw.DisableDatagramHandling()
	go handleUniStreams(qconn, raw.HandleUnidirectionalStream)
	go handleBidiStreams(qconn, func(stream *quic.Stream) {
		frameType, err := peekFrameType(stream)
		if err != nil {
			rejectStream(stream)
			return
		}
		if frameType != SSH_FRAME_TYPE {
			raw.HandleBidirectionalStream(stream)
			return
		}
		select {
		case <-ready:
			if !established {
				rejectStream(stream)
				return
			}
		case <-qconn.Context().Done():
			rejectStream(stream)
			return
		}
		if _, err = util.ReadVarInt(&StreamByteReader{stream}); err == nil {
			err = c.acceptSSHChannel(stream)
		}
		if err != nil {
			rejectStream(stream)
		}
	})

	select {
	case <-raw.ReceivedSettings():
		// Supported SSH3 0.1.5 servers implement CONNECT without advertising the
		// later HTTP/3 setting. Keep version negotiation, TLS and auth checks below.

	case <-req.Context().Done():
		return req.Context().Err()
	case <-qconn.Context().Done():
		return context.Cause(qconn.Context())
	}

	doReq := func(version Version, req *http.Request) (*http.Response, Version, error) {
		req.Header.Set("User-Agent", version.GetVersionString())
		log.Debug().Msgf("send %s request on URL %s, User-Agent=\"%s\"", req.Method, req.URL, req.Header.Get("User-Agent"))
		stream, err := raw.OpenRequestStream(req.Context())
		if err != nil {
			return nil, Version{}, err
		}
		c.controlStream = stream
		if err = stream.SendRequestHeader(req); err != nil {
			rejectStream(stream)
			return nil, Version{}, err
		}
		stop := context.AfterFunc(req.Context(), func() { rejectStream(stream) })
		defer stop()
		rsp, err := stream.ReadResponse()
		if err != nil {
			return rsp, Version{}, err
		}

		log.Debug().Msgf("got response with %s status code", rsp.Status)

		serverVersionStr := rsp.Header.Get("Server")
		serverVersion, err := ParseVersionString(serverVersionStr)
		if err != nil {
			log.Error().Msgf("Could not parse server version: \"%s\"", serverVersionStr)
			if rsp.StatusCode == 200 {
				return rsp, Version{}, InvalidSSHVersion{versionString: serverVersionStr}
			}
		} else {
			log.Debug().Msgf("server has valid version \"%s\" (protocol version = %s, software version = %s)",
				serverVersionStr, serverVersion.GetProtocolVersion(), serverVersion.GetSoftwareVersion())
		}
		return rsp, serverVersion, nil
	}

	rsp, serverVersion, err := doReq(ThisVersion(), req)
	if err != nil {
		return err
	}

	serverProtocolVersion := serverVersion.GetProtocolVersion()
	thisProtocolVersion := ThisVersion().GetProtocolVersion()
	if rsp.StatusCode == http.StatusForbidden && serverProtocolVersion != thisProtocolVersion {
		// This version negotiation code might feel a bit heavy but is only there for a smooth transition
		// between early versions and versions coming from an actual IETF specification that include
		// proper version negotiation. Older version of this implementation strictly check the exact protocol
		// version (i.e. must be 3.0) and then check the software version. In next iterations, everything will be
		// based on the protocol version for better interoperability.

		// see if there is an exact version match (including software version, which is useful
		// for old versions that do not support version negotiation based on the protocol version)
		matchingVersionIndex := slices.Index(supportedVersions, serverVersion)

		// there is no exact match, the implementation/software version might differ, but the
		// protocol version may still match
		if matchingVersionIndex == -1 {
			matchingVersionIndex = slices.IndexFunc(supportedVersions, func(supportedVersion Version) bool {
				return serverProtocolVersion == supportedVersion.GetProtocolVersion()
			})
		}
		if matchingVersionIndex != -1 {
			log.Warn().Msgf("The server runs an old version of the protocol (%s). This software is still experimental, "+
				"you may want to update the server version before support is removed. Also, note that connecting to old "+
				"servers may increase the connection establishment time.", serverVersion.GetVersionString())
			rsp.Body.Close()
			c.controlStream.Close()
			// now retry the request with the compatible version
			rsp, serverVersion, err = doReq(supportedVersions[matchingVersionIndex], req)
			if err != nil {
				return err
			}
		}
	}

	if rsp.StatusCode == 200 {
		if !IsVersionSupported(serverVersion) {
			log.Warn().Msgf("The server runs an unsupported SSH version (%s), you may want to consider to update the client (currently %s)",
				serverVersion.GetProtocolVersion(), ThisVersion().GetProtocolVersion())
		}
		go func() {
			// TODO: this hijacks the datagrams for the whole quic connection, so the server
			//		 currently does not work for several conversations in the same QUIC connection

			for {
				dgram, err := qconn.ReceiveDatagram(c.Context())
				if err != nil {
					if err != context.Canceled {
						log.Error().Msgf("could not receive message from conn: %s", err)
					}
					return
				}
				buf := &util.BytesReadCloser{Reader: bytes.NewReader(dgram)}
				convID, err := util.ReadVarInt(buf)
				if err != nil {
					log.Error().Msgf("could not read conv id from datagram on conv %d: %s", c.controlStream.StreamID(), err)
					return
				}
				if convID == uint64(c.controlStream.StreamID()) {
					err = c.AddDatagram(c.Context(), dgram[buf.Size()-int64(buf.Len()):])
					if err != nil {
						if _, queued := err.(util.ChannelNotFound); queued {
							continue
						}
						log.Error().Msgf("could not add datagram to conv id %d: %s", c.controlStream.StreamID(), err)
						return
					}
				} else {
					log.Error().Msgf("discarding datagram with invalid conv id %d", convID)
				}
			}
		}()
		c.peerVersion = serverVersion
		established = true
		return nil
	} else if rsp.StatusCode == http.StatusUnauthorized {
		rsp.Body.Close()
		c.controlStream.Close()
		return util.Unauthorized{}
	} else {
		bodyContent, err := io.ReadAll(io.LimitReader(rsp.Body, 1<<20))
		rsp.Body.Close()
		if err != nil {
			log.Error().Msgf("could not read response body from server: %s", err)
		}

		return util.OtherHTTPError{
			HasBody:    rsp.ContentLength > 0,
			Body:       string(bodyContent),
			StatusCode: rsp.StatusCode,
		}
	}
}

func NewServerConversation(ctx context.Context, controlStream Stream, qconn *quic.Conn, messageSender util.DatagramSender, maxPacketsize uint64, peerVersion Version) (*Conversation, error) {
	if err := validatePacketSize(maxPacketsize); err != nil {
		return nil, err
	}
	tls := qconn.ConnectionState().TLS
	convID, err := GenerateConversationID(&tls)
	if err != nil {
		log.Error().Msgf("could not generate conversation ID on server")
		return nil, err
	}

	backgroundContext, backgroundCancelFunc := context.WithCancelCause(ctx)

	conv := &Conversation{
		controlStream:       controlStream,
		channelsAcceptQueue: util.NewAcceptQueue[Channel](),
		streamCreator:       qconn,
		maxPacketSize:       maxPacketsize,
		messageSender:       messageSender,
		channelsManager:     newChannelsManager(),
		context:             backgroundContext,
		cancelContext:       backgroundCancelFunc,
		conversationID:      convID,
		peerVersion:         peerVersion,
	}
	return conv, nil
}

type StreamByteReader struct {
	Stream
}

func (r *StreamByteReader) ReadByte() (byte, error) {
	buf := [1]byte{0}
	_, err := io.ReadFull(r.Stream, buf[:])
	if err != nil {
		return 0, err
	}
	return buf[0], nil
}

func (c *Conversation) OpenChannel(channelType string, maxPacketSize uint64, datagramsQueueSize uint64) (Channel, error) {
	if err := validatePacketSize(maxPacketSize); err != nil {
		return nil, err
	}
	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), channelType, maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, nil)
	c.channelsManager.addChannel(channel)
	return channel, nil
}

func (c *Conversation) OpenUDPForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.UDPAddr, remoteAddr *net.UDPAddr) (Channel, error) {
	if err := validatePacketSize(maxPacketSize); err != nil {
		return nil, err
	}

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	additionalBytes := buildForwardingChannelAdditionalBytes(remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "direct-udp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.setDatagramSender(c.getDatagramSenderForChannel(channel.ChannelID()))
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &UDPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr}, nil
}

func (c *Conversation) OpenTCPForwardingChannel(maxPacketSize uint64, datagramsQueueSize uint64, localAddr *net.TCPAddr, remoteAddr *net.TCPAddr) (Channel, error) {
	if err := validatePacketSize(maxPacketSize); err != nil {
		return nil, err
	}

	str, err := c.streamCreator.OpenStream()
	if err != nil {
		return nil, err
	}
	additionalBytes := buildForwardingChannelAdditionalBytes(remoteAddr.IP, uint16(remoteAddr.Port))

	channel := NewChannel(uint64(c.controlStream.StreamID()), c.conversationID, uint64(str.StreamID()), "direct-tcp", maxPacketSize, &StreamByteReader{str}, str, nil, c.channelsManager, true, true, false, datagramsQueueSize, additionalBytes)
	channel.maybeSendHeader()
	c.channelsManager.addChannel(channel)
	return &TCPForwardingChannelImpl{Channel: channel, RemoteAddr: remoteAddr}, nil
}

func (c *Conversation) AcceptChannel(ctx context.Context) (Channel, error) {
	for {
		if channel := c.channelsAcceptQueue.Next(); channel != nil {
			channel.confirmChannel(c.maxPacketSize)
			c.channelsManager.addChannel(channel)
			return channel, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-c.channelsAcceptQueue.Chan():
		}
	}

}

// blocks until the datagram is added
// the first field must be the channel ID
func (c *Conversation) AddDatagram(ctx context.Context, datagram []byte) error {
	buf := &util.BytesReadCloser{Reader: bytes.NewReader(datagram)}
	channelID, err := util.ReadVarInt(buf)
	if err != nil {
		return err
	}
	channel, ok := c.channelsManager.getChannel(channelID)
	if !ok {
		dgramQueue := util.NewDatagramsQueue(10)
		dgramQueue.Add(datagram[buf.Size()-int64(buf.Len()):])
		c.channelsManager.addDanglingDatagramsQueue(channelID, dgramQueue)
		return util.ChannelNotFound{ChannelID: channelID}
	}
	return channel.waitAddDatagram(ctx, datagram[buf.Size()-int64(buf.Len()):])
}

func (c *Conversation) Close() {
	if c.controlStream != nil {
		c.controlStream.Close()
		c.controlStream.CancelRead(0)
	}
	c.cancelContext(nil)
}

func (c *Conversation) Context() context.Context {
	return c.context
}

func (c *Conversation) getDatagramSenderForChannel(channelID util.ChannelID) func(datagram []byte) error {
	return func(datagram []byte) error {
		buf := util.AppendVarInt(nil, uint64(c.controlStream.StreamID()))
		buf = util.AppendVarInt(buf, channelID)
		buf = append(buf, datagram...)
		return c.messageSender.SendDatagram(buf)
	}
}

func (c *Conversation) ConversationID() ConversationID {
	return c.conversationID
}

func (c *Conversation) acceptSSHChannel(stream *quic.Stream) error {
	controlStreamID, channelType, maxPacketSize, err := parseHeader(uint64(stream.StreamID()), &StreamByteReader{stream})
	if err != nil {
		return err
	}
	// todo: handle several conversations for the same client on the same connection ?
	// This can be done by defining the conversation ID as a combination between the control stream ID
	// and the tls exporter value, or computing the exporter value depending on the stream ID
	if controlStreamID != uint64(c.controlStream.StreamID()) {
		err := fmt.Errorf("wrong conversation control stream ID: %d instead of expected %d", controlStreamID, c.controlStream.StreamID())
		log.Error().Msgf("%s", err)
		return err
	}
	channelInfo := &ChannelInfo{
		ConversationID:       c.ConversationID(),
		ConversationStreamID: controlStreamID,
		ChannelID:            uint64(stream.StreamID()),
		ChannelType:          channelType,
		MaxPacketSize:        maxPacketSize,
	}

	newChannel := NewChannel(channelInfo.ConversationStreamID, channelInfo.ConversationID, uint64(stream.StreamID()), channelInfo.ChannelType, channelInfo.MaxPacketSize, &StreamByteReader{stream}, stream, nil, c.channelsManager, false, false, true, c.defaultDatagramsQueueSize, nil)
	newChannel.setDatagramSender(c.getDatagramSenderForChannel(newChannel.ChannelID()))
	c.channelsAcceptQueue.Add(newChannel)
	return nil
}
