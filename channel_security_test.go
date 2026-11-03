package ssh3

import (
	"bytes"
	"context"
	"io"
	"sync"
	"testing"

	"github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
)

func TestChannelHeaderBoundsPacketSize(t *testing.T) {
	for _, size := range []uint64{0, 1, 63, util.MaxSSHStringLength + 1, util.Max} {
		encoded := buildHeader(0, "session", size, nil)
		reader := bytes.NewReader(encoded)
		_, _ = util.ReadVarInt(reader)
		if _, _, _, err := parseHeader(4, reader); err == nil {
			t.Fatalf("accepted packet size %d", size)
		}
	}
	for _, size := range []uint64{64, 30_000, util.MaxSSHStringLength} {
		reader := bytes.NewReader(buildHeader(0, "session", size, nil))
		_, _ = util.ReadVarInt(reader)
		if _, _, _, err := parseHeader(4, reader); err != nil {
			t.Fatalf("rejected packet size %d: %v", size, err)
		}
	}
}

func TestConcurrentChannelWritersSendOneHeader(t *testing.T) {
	writer := &bufferWriteCloser{}
	channel := &channelImpl{ChannelInfo: ChannelInfo{MaxPacketSize: 300}, send: writer, header: buildHeader(0, "session", 300, nil)}
	var group sync.WaitGroup
	for range 8 {
		group.Go(func() {
			if _, err := channel.WriteData([]byte("data"), message.SSH_EXTENDED_DATA_NONE); err != nil {
				t.Error(err)
			}
		})
	}
	group.Wait()
	reader := bytes.NewReader(writer.Bytes())
	if frame, err := util.ReadVarInt(reader); err != nil || frame != SSH_FRAME_TYPE {
		t.Fatalf("channel frame: %d, %v", frame, err)
	}
	if _, _, _, err := parseHeader(4, reader); err != nil {
		t.Fatal(err)
	}
	for range 8 {
		parsed, err := message.ParseMessage(reader)
		if err != nil || parsed.(*message.DataOrExtendedDataMessage).Data != "data" {
			t.Fatalf("concurrent message: %v, %v", parsed, err)
		}
	}
	if reader.Len() != 0 {
		t.Fatal("duplicate header or trailing channel data")
	}
}

func TestReorderedDatagramsStayBoundedAndPreserveOrder(t *testing.T) {
	manager := newChannelsManager()
	conversation := &Conversation{channelsManager: manager}
	for _, payload := range []string{"first", "second"} {
		_ = conversation.AddDatagram(context.Background(), append(util.AppendVarInt(nil, 4), payload...))
	}
	channel := &channelImpl{ChannelInfo: ChannelInfo{ChannelID: 4}}
	manager.addChannel(channel)
	for _, want := range []string{"first", "second"} {
		if got := channel.datagramsQueue.Next(); string(got) != want {
			t.Fatalf("queued datagram = %q, want %q", got, want)
		}
	}
	for id := uint64(8); id < 1000; id++ {
		_ = conversation.AddDatagram(context.Background(), append(util.AppendVarInt(nil, id), 'x'))
	}
	if len(manager.danglingDgramQueues) > maxDanglingDatagramChannels {
		t.Fatal("peer-controlled channel IDs created unbounded datagram queues")
	}
}

type bufferWriteCloser struct{ bytes.Buffer }

func (w *bufferWriteCloser) Close() error { return nil }

func TestWriteDataRejectsInvalidSizeAndBoundsEncodedPackets(t *testing.T) {
	for _, size := range []uint64{0, 1, 63, util.Max} {
		channel := &channelImpl{ChannelInfo: ChannelInfo{MaxPacketSize: size}, send: &bufferWriteCloser{}}
		if _, err := channel.WriteData([]byte("data"), message.SSH_EXTENDED_DATA_STDERR); err == nil {
			t.Fatalf("accepted packet size %d", size)
		}
	}
	for _, dataType := range []message.SSHDataType{message.SSH_EXTENDED_DATA_NONE, message.SSH_EXTENDED_DATA_STDERR} {
		writer := &bufferWriteCloser{}
		channel := &channelImpl{ChannelInfo: ChannelInfo{MaxPacketSize: 300}, send: writer}
		payload := bytes.Repeat([]byte("x"), 2048)
		n, err := channel.WriteData(payload, dataType)
		if err != nil || n != len(payload) {
			t.Fatalf("write returned %d, %v", n, err)
		}
		var decoded []byte
		for writer.Len() > 0 {
			before := writer.Len()
			parsed, err := message.ParseMessage(util.NewReader(writer))
			if err != nil && err != io.EOF {
				t.Fatal(err)
			}
			if before-writer.Len() > 300 {
				t.Fatal("encoded packet exceeds advertised maximum")
			}
			decoded = append(decoded, parsed.(*message.DataOrExtendedDataMessage).Data...)
		}
		if !bytes.Equal(decoded, payload) {
			t.Fatal("data changed during packet splitting")
		}
	}
}
