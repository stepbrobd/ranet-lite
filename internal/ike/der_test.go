package ike

import (
	"bytes"
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
