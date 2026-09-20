package main

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/flynn/noise"
)

type request struct {
	PSK       string   `json:"psk"`
	Prologue  string   `json:"prologue"`
	Initiator string   `json:"initiator"`
	Responder string   `json:"responder"`
	Payloads  []string `json:"payloads"`
}

type response struct {
	Hash     string   `json:"hash"`
	Messages []string `json:"messages"`
}

func decode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func transcript(input request) (response, error) {
	newPeer := func(initiator bool, entropy string) (*noise.HandshakeState, error) {
		return noise.NewHandshakeState(noise.Config{
			CipherSuite:           noise.NewCipherSuite(noise.DH25519, noise.CipherAESGCM, noise.HashSHA256),
			Pattern:               noise.HandshakeNN,
			Initiator:             initiator,
			PresharedKey:          decode(input.PSK),
			PresharedKeyPlacement: 0,
			Prologue:              decode(input.Prologue),
			Random:                bytes.NewReader(decode(entropy)),
		})
	}
	a, err := newPeer(true, input.Initiator)
	if err != nil {
		return response{}, err
	}
	b, err := newPeer(false, input.Responder)
	if err != nil {
		return response{}, err
	}
	first, _, _, err := a.WriteMessage(nil, decode(input.Payloads[0]))
	if err != nil {
		return response{}, err
	}
	if _, _, _, err = b.ReadMessage(nil, first); err != nil {
		return response{}, err
	}
	second, brx, btx, err := b.WriteMessage(nil, decode(input.Payloads[1]))
	if err != nil {
		return response{}, err
	}
	_, atx, arx, err := a.ReadMessage(nil, second)
	if err != nil {
		return response{}, err
	}
	result := response{Hash: hex.EncodeToString(a.ChannelBinding()), Messages: []string{hex.EncodeToString(first), hex.EncodeToString(second)}}
	if !bytes.Equal(a.ChannelBinding(), b.ChannelBinding()) {
		return response{}, fmt.Errorf("reference binding mismatch")
	}
	senders, receivers := []*noise.CipherState{atx, btx}, []*noise.CipherState{brx, arx}
	for i, payload := range input.Payloads[2:] {
		ciphertext, err := senders[i%2].Encrypt(nil, nil, decode(payload))
		if err != nil {
			return response{}, err
		}
		plaintext, err := receivers[i%2].Decrypt(nil, nil, ciphertext)
		if err != nil || !bytes.Equal(plaintext, decode(payload)) {
			return response{}, fmt.Errorf("reference transport mismatch: %w", err)
		}
		result.Messages = append(result.Messages, hex.EncodeToString(ciphertext))
	}
	return result, nil
}

func main() {
	reader, writer := json.NewDecoder(os.Stdin), json.NewEncoder(os.Stdout)
	for {
		var input request
		if err := reader.Decode(&input); err == io.EOF {
			return
		} else if err != nil {
			panic(err)
		}
		result, err := transcript(input)
		if err != nil {
			panic(err)
		}
		if err := writer.Encode(result); err != nil {
			panic(err)
		}
	}
}
