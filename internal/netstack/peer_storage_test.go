package netstack

import (
	"bytes"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestReservedPeerKeepsCiphertextUntilSendCompletes(t *testing.T) {
	for _, sendErr := range []error{nil, errors.New("transport failed")} {
		t.Run(fmt.Sprint(sendErr), func(t *testing.T) {
			started := make(chan struct{})
			release := make(chan struct{})
			var once sync.Once
			var sent []byte
			p := NewPeerReserved("peer", func(int) (BatchSealer, error) {
				return func(raw [][]byte, _ []byte, reuse [][]byte) ([][]byte, error) {
					if len(reuse) == 0 {
						reuse = [][]byte{{0}}
					}
					reuse[0][0] = raw[0][0]
					return reuse, nil
				}, nil
			}, func(packets [][]byte) error {
				if len(sent) == 0 {
					close(started)
					<-release
				}
				for _, packet := range packets {
					sent = append(sent, packet[0])
				}
				return sendErr
			})
			t.Cleanup(func() { once.Do(func() { close(release) }); p.Close() })
			first := p.reserveBatch(1)
			first.append([]byte{1}, 0)
			first.done = make(chan error, 1)
			if err := first.enqueue(); err != nil {
				t.Fatal(err)
			}
			select {
			case <-started:
			case <-time.After(time.Second):
				t.Fatal("sender did not start")
			}
			if first.storage == nil {
				t.Fatal("ciphertext recycled while transport still owns it")
			}
			second := p.reserveBatch(1)
			second.append([]byte{2}, 0)
			second.done = make(chan error, 1)
			if err := second.enqueue(); err != nil {
				t.Fatal(err)
			}
			once.Do(func() { close(release) })
			for _, b := range []*peerBatch{first, second} {
				select {
				case err := <-b.done:
					if !errors.Is(err, sendErr) {
						t.Fatalf("send result = %v, want %v", err, sendErr)
					}
				case <-time.After(time.Second):
					t.Fatal("sender did not complete")
				}
				if b.storage != nil || b.sealed != nil {
					t.Fatal("completed batch retained pooled ciphertext")
				}
			}
			if !bytes.Equal(sent, []byte{1, 2}) {
				t.Fatalf("in-flight ciphertext was overwritten: got %v", sent)
			}
		})
	}
}
