package xmpp

import (
	"encoding/base64"
	"crypto/rand"
	"crypto/hmac"
	"hash"
	"strings"
	"strconv"
	"fmt"
)

func saslEncodePlain(user, password string) string {
	return base64.StdEncoding.EncodeToString([]byte("\x00" + user + "\x00" + password))
}

func createScramFunction(h func()hash.Hash) func(*Stream, string, string) error {



	return func (stream *Stream, user, password string) error {
		Hi := func (message string, salt string, iterations int) ([]byte, error) {
			byte_message := []byte(message)
			mac := hmac.New(h, byte_message)
			byte_salt, err := base64.StdEncoding.DecodeString(salt)
			if err != nil {
				return nil, err
			}
			m_salt := make([]byte, len(byte_salt) + 4)
			copy(m_salt, byte_salt)
			m_salt[len(m_salt)-1] = 1
			mac.Write(m_salt)
			lastVal := mac.Sum([]byte{})
			var newVal []byte

			rVal := lastVal

			for count:= 1; count < iterations; count += 1 {
				mac := hmac.New(h, byte_message)
				mac.Write(lastVal)
				newVal = mac.Sum([]byte{})
				for i := range rVal {
					rVal[i] ^= newVal[i]
				}
				lastVal = newVal
			}
			return rVal, nil
		}

		nBytes := make([]byte, 16)
		rand.Read(nBytes)
		clientNonce :=  base64.StdEncoding.EncodeToString(nBytes)
		initialClient := fmt.Sprintf("n,,n=%s,r=%s", user, clientNonce)
		var combinedNonce, salt, iterationCount string
		auth := saslAuth{Mechanism: "SCRAM-SHA-1", Text: base64.StdEncoding.EncodeToString([]byte(initialClient)) }
		if err := stream.Send(&auth); err != nil {
			return err
		}
		challenge := saslChallenge{}
		if err := stream.Decode(&challenge, nil); err != nil {
			return err
		}
		saslChallenge, err := base64.StdEncoding.DecodeString(challenge.Text)
		if err != nil {
			return err
		}
		challengeFields := strings.Split(string(saslChallenge), ",")
		for _,field := range challengeFields {
			keyval := strings.SplitN(field, "=", 2)
			switch keyval[0]{

			case "r":
				combinedNonce = keyval[1]
			case "s":
				salt = keyval[1]
			case "i":
				iterationCount = keyval[1]
			}
		}
		i_count, err := strconv.ParseInt(iterationCount, 10, 32)
		if err != nil {
			return err
		}
		salted_password, err := Hi(password, salt, int(i_count))
		if err != nil {
			return err
		}
		mac := hmac.New(h, salted_password)
		mac.Write([]byte("Client Key"))
		client_key := mac.Sum([]byte{})
		h_func := h()
		h_func.Write(client_key)
		stored_key := h_func.Sum([]byte{})
		auth_message := fmt.Sprintf("n=%s,r=%s,%s,c=biws,r=%s", user, clientNonce, string(saslChallenge), combinedNonce)
		mac = hmac.New(h, stored_key)
		mac.Write([]byte(auth_message))
		client_sig := mac.Sum([]byte{})
		client_proof := client_key
		for i := range client_sig {
			client_proof[i] ^= client_sig[i]
		}

		if err != nil {
			return err
		}
		proof_message := fmt.Sprintf("c=biws,r=%s,p=%s", combinedNonce, base64.StdEncoding.EncodeToString(client_proof))
		response := saslResponse{Text:  base64.StdEncoding.EncodeToString([]byte(proof_message))}

		if err := stream.Send(&response); err != nil {
			return err
		}
		return authenticateResponse(stream)
	}
}
