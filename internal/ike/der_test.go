package ike

import (
	"bytes"
	"strings"
	"testing"
)

// DER requires the shortest length encoding, and a peer's identity is the name
// this parser reads out of the bytes it was sent. Accepting a second spelling
// of one length makes two byte sequences decode to the same name.
func TestDERLengthMustBeMinimal(t *testing.T) {
	content := bytes.Repeat([]byte{0x41}, 200)
	for name, header := range map[string][]byte{
		"long form for a length the short form holds": {0x04, 0x81, 0x05},
		"one leading zero octet":                      {0x04, 0x82, 0x00, 0xc8},
		"three leading zero octets":                   {0x04, 0x84, 0x00, 0x00, 0x00, 0xc8},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := derElement(append(header, content...)); err == nil {
				t.Error("a non-minimal length was accepted, so one name has more than one encoding")
			}
		})
	}

	// The minimal spellings still parse.
	if _, body, _, err := derElement(append([]byte{0x04, 0x05}, content[:5]...)); err != nil || len(body) != 5 {
		t.Errorf("the short form was refused: body %d bytes, err %v", len(body), err)
	}
	if _, body, _, err := derElement(append([]byte{0x04, 0x81, 0xc8}, content...)); err != nil || len(body) != 200 {
		t.Errorf("the minimal long form was refused: body %d bytes, err %v", len(body), err)
	}
}

// The length octets come out of a peer's certificate, and four of them spell
// values no int on a 32 bit build can hold: 0xffffffff is negative there, and
// what caught it was a minimality test meant for something else, which called
// the same bytes non-minimal on one build and truncated on another.
//
// The word size is the whole point, so on amd64 this passes with the bound in
// derElement deleted: the later length test produces the same message. On 386
// it does not, and deleting the bound panics on the slice rather than
// refusing. `CGO_ENABLED=0 GOARCH=386 go test ./internal/ike/ -run TestDER`
// on x86_64-linux holds it; do not read a green run here as proof.
func TestDERLengthBeyondTheBufferIsRefusedNotSliced(t *testing.T) {
	for name, raw := range map[string][]byte{
		"four octets, all ones": {0x04, 0x84, 0xff, 0xff, 0xff, 0xff, 1, 2, 3},
		"four octets, high bit": {0x04, 0x84, 0x80, 0, 0, 0, 1, 2, 3},
		"three octets":          {0x04, 0x83, 0xff, 0xff, 0xff, 1, 2, 3},
		"one octet":             {0x04, 0x81, 0xff, 1, 2, 3},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := derElement(raw)
			if err == nil {
				t.Fatal("a length larger than the element was accepted")
			}
			// The message matters here: the pre-existing minimality test also
			// refuses these, but only on a build where the accumulator went
			// negative, so one certificate was called non-minimal on a 32 bit
			// build and truncated on a 64 bit one.
			if !strings.Contains(err.Error(), "truncated DER content") {
				t.Errorf("the refusal reads %q, which is a different reason on a different word size", err)
			}
		})
	}
	// A four octet length that does fit is still read, so the bound is on what
	// is there rather than on the spelling.
	body := make([]byte, 1<<16)
	raw := append([]byte{0x04, 0x84, 0x00, 0x01, 0x00, 0x00}, body...)
	// The leading zero octet is not minimal DER, which is its own refusal.
	if _, _, _, err := derElement(raw); err == nil {
		t.Error("a non-minimal four octet length was accepted")
	}
	raw = append([]byte{0x04, 0x83, 0x01, 0x00, 0x00}, body...)
	tag, content, rest, err := derElement(raw)
	if err != nil || tag != 0x04 || len(content) != 1<<16 || len(rest) != 0 {
		t.Errorf("a three octet length that fits read tag %#x, %d bytes, %d left, err %v", tag, len(content), len(rest), err)
	}
}
