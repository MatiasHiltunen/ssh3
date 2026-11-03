package util

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestSSHStringRejectsOversizedLengthBeforeReadingPayload(t *testing.T) {
	for _, size := range []uint64{MaxSSHStringLength + 1, 1 << 32, Max} {
		reader := bytes.NewReader(AppendVarInt(nil, size))
		if _, err := ParseSSHString(reader); err == nil {
			t.Fatalf("accepted untrusted length %d without a payload", size)
		}
	}
}

func TestSSHStringValidAndTruncatedPayloads(t *testing.T) {
	for _, value := range []string{"", "SSH3", strings.Repeat("x", 5_000_000)} {
		encoded := append(AppendVarInt(nil, uint64(len(value))), value...)
		got, err := ParseSSHString(bytes.NewReader(encoded))
		if err != nil || got != value {
			t.Fatalf("round trip length %d: got length %d, error %v", len(value), len(got), err)
		}
	}
	if _, err := ParseSSHString(bytes.NewReader([]byte{5, 'x'})); err == nil {
		t.Fatal("accepted truncated SSH string")
	}
}

type emptyThenByteReader struct{ calls int }

func (r *emptyThenByteReader) Read(out []byte) (int, error) {
	r.calls++
	if r.calls == 1 {
		return 0, nil
	}
	out[0] = 42
	return 1, io.EOF
}

func TestByteReaderHandlesShortReadsAndEOF(t *testing.T) {
	reader := NewReader(&emptyThenByteReader{})
	if got, err := reader.ReadByte(); err != nil || got != 42 {
		t.Fatalf("short read produced %d, %v", got, err)
	}
	if _, err := NewReader(io.LimitReader(strings.NewReader(""), 0)).ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("empty reader returned %v", err)
	}
}

func FuzzParseSSHString(f *testing.F) {
	for _, input := range [][]byte{{}, {0}, {3, 's', 's', 'h'}, AppendVarInt(nil, Max), {5, 'x'}} {
		f.Add(input)
	}
	f.Fuzz(func(t *testing.T, input []byte) {
		_, _ = ParseSSHString(bytes.NewReader(input))
	})
}
