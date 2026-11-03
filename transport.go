package ssh3

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/francoismichel/ssh3/util"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// ReceiveStream is the receive half used by channels, including framed HTTP/3 streams.
type ReceiveStream interface {
	io.Reader
	CancelRead(quic.StreamErrorCode)
}

// Stream is implemented by QUIC streams and HTTP/3 CONNECT request streams.
type Stream interface {
	ReceiveStream
	io.WriteCloser
	StreamID() quic.StreamID
	CancelWrite(quic.StreamErrorCode)
}

type quicConnectionKey struct{}

// QUICConnectionFromRequest retrieves the transport connection installed by Server.
func QUICConnectionFromRequest(r *http.Request) (*quic.Conn, bool) {
	conn, ok := r.Context().Value(quicConnectionKey{}).(*quic.Conn)
	return conn, ok
}

func rejectStream(stream Stream) {
	stream.CancelRead(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
	stream.CancelWrite(quic.StreamErrorCode(http3.ErrCodeRequestRejected))
}

// Peek leaves HTTP/3 request bytes untouched for the upstream HTTP/3 parser.
func peekFrameType(stream *quic.Stream) (uint64, error) {
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	defer stream.SetReadDeadline(time.Time{})
	var buf [8]byte
	if n, err := stream.Peek(buf[:1]); n < 1 {
		return 0, err
	}
	n := 1 << (buf[0] >> 6)
	if read, err := stream.Peek(buf[:n]); read < n {
		return 0, err
	}
	return util.ReadVarInt(bytes.NewReader(buf[:n]))
}

func handleUniStreams(conn *quic.Conn, handle func(*quic.ReceiveStream)) {
	for {
		stream, err := conn.AcceptUniStream(conn.Context())
		if err != nil {
			return
		}
		go handle(stream)
	}
}

func handleBidiStreams(conn *quic.Conn, handle func(*quic.Stream)) {
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return
		}
		go handle(stream)
	}
}

// Serve accepts SSH3 channels alongside HTTP/3 requests on the same QUIC connection.
func (s *Server) Serve(packetConn net.PacketConn) error {
	if err := validatePacketSize(s.maxPacketSize); err != nil {
		return err
	}
	if s.h3Server.TLSConfig == nil {
		return fmt.Errorf("SSH3 server requires a TLS configuration")
	}
	cfg := &quic.Config{}
	if s.h3Server.QUICConfig != nil {
		cfg = s.h3Server.QUICConfig.Clone()
	}
	cfg.EnableDatagrams = s.h3Server.EnableDatagrams
	listener, err := quic.ListenEarly(packetConn, http3.ConfigureTLSConfig(s.h3Server.TLSConfig), cfg)
	if err != nil {
		return err
	}
	s.lock.Lock()
	if s.closed {
		s.lock.Unlock()
		listener.Close()
		return http.ErrServerClosed
	}
	s.listener = listener
	s.lock.Unlock()
	defer listener.Close()
	for {
		conn, err := listener.Accept(context.Background())
		if err != nil {
			return err
		}
		s.lock.Lock()
		if s.closed {
			s.lock.Unlock()
			conn.CloseWithError(0, "server closed")
			return http.ErrServerClosed
		}
		s.connections[conn] = struct{}{}
		s.lock.Unlock()
		go s.serveConnection(conn)
	}
}

func (s *Server) ListenAndServe() error {
	addr := s.h3Server.Addr
	if addr == "" {
		addr = ":https"
	}
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	return s.Serve(conn)
}

func (s *Server) Close() error {
	s.lock.Lock()
	s.closed = true
	listener := s.listener
	connections := make([]*quic.Conn, 0, len(s.connections))
	for conn := range s.connections {
		connections = append(connections, conn)
	}
	s.lock.Unlock()
	for _, conn := range connections {
		_ = conn.CloseWithError(0, "server closed")
	}
	if listener != nil {
		return listener.Close()
	}
	return nil
}

func (s *Server) serveConnection(conn *quic.Conn) {
	defer s.removeConnection(conn)
	defer conn.CloseWithError(0, "connection closed")
	raw, err := s.h3Server.NewRawServerConn(conn)
	if err != nil {
		return
	}
	// SSH3 datagrams use the full control stream ID, rather than RFC 9297's quarter ID.
	raw.DisableDatagramHandling()
	go handleUniStreams(conn, raw.HandleUnidirectionalStream)
	go s.receiveDatagrams(conn)
	handleBidiStreams(conn, func(stream *quic.Stream) {
		frameType, err := peekFrameType(stream)
		if err != nil {
			rejectStream(stream)
			return
		}
		if frameType != SSH_FRAME_TYPE {
			raw.HandleRequestStream(stream)
			return
		}
		if _, err = util.ReadVarInt(&StreamByteReader{stream}); err == nil {
			err = s.acceptSSHChannel(conn, stream)
		}
		if err != nil {
			rejectStream(stream)
		}
	})
}

// Exactly one receiver routes datagrams to authenticated conversations per connection.
func (s *Server) receiveDatagrams(conn *quic.Conn) {
	for {
		datagram, err := conn.ReceiveDatagram(conn.Context())
		if err != nil {
			return
		}
		reader := bytes.NewReader(datagram)
		id, err := util.ReadVarInt(reader)
		if err != nil {
			continue
		}
		manager, ok := s.getConversationsManager(conn)
		if !ok {
			continue
		}
		conv, ok := manager.getConversation(id)
		if !ok {
			continue
		}
		_ = conv.AddDatagram(conv.Context(), datagram[len(datagram)-reader.Len():])
	}
}

func validatePacketSize(size uint64) error {
	// Reserve room for the largest data-message header and its length varint.
	if size < 64 || size > util.MaxSSHStringLength {
		return fmt.Errorf("SSH3 packet size %d outside allowed range [64, %d]", size, util.MaxSSHStringLength)
	}
	return nil
}
