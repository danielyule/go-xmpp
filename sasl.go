package xmpp

import (
	"encoding/base64"
	"crypto/rand"
	"crypto/hmac"
	"hash"
	"strings"
	"strconv"
	"fmt"
	"encoding/xml"
)




func saslAuthentication(stream *Stream, user, password string, handler authHandler) error {
	var challengeText []byte
	initial_message, err := handler.Mechanism.initialMessage(user, password)
	if err != nil {
		return err
	}
	auth := saslAuth{Mechanism: handler.Name, Text: base64.StdEncoding.EncodeToString([]byte(initial_message)) }
	if err := stream.Send(&auth); err != nil {
		return err
	}

	//Loop as long as we keep getting <challenge> tags
	for {
		if se, err := stream.Next(); err != nil {
			return err
		} else {
			switch se.Name.Local {
			case "challenge":
				challenge := new(saslChallenge)
				if err := stream.Decode(challenge, se); err != nil {
					return err
				}
				challengeText, err = base64.StdEncoding.DecodeString(challenge.Text)
				if err != nil {
					return err
				}
			case "success":
				if err := stream.Skip(); err != nil {
					return err
				}
				return nil
			case "failure":
				f := new(saslFailure)
				if err := stream.Decode(f, se); err != nil {
					return err
				}
				return fmt.Errorf("Authentication failed: %s", f.Reason.Local)
			default:
				return fmt.Errorf("Unexpected: %s", se.Name)
			}
		}
		response, err := handler.Mechanism.challengeResponse(string(challengeText))
		if err != nil {
			return err
		}
		saslSendResponse(stream, response)
	}
	return nil
}

type saslAuth struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl auth"`
	Mechanism string   `xml:"mechanism,attr"`
	Text      string   `xml:",chardata"`
}

type saslChallenge struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl challenge"`
	Text      string   `xml:",chardata"`
}

type saslResponse struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl response"`
	Text      string   `xml:",chardata"`
}

type saslMechanism interface {
	initialMessage(user, password string) (string, error)
	challengeResponse(challenge string) (string, error)
}

type SaslPLAIN struct {

}

func (*SaslPLAIN)initialMessage(user, password string) (string, error) {
	return "\x00" + user + "\x00" + password, nil
}

func (*SaslPLAIN)challengeResponse(challenge string) (string, error) {
	panic("Should never be called")
}


type SaslCRAM struct {
	hash_func func()hash.Hash
	client_nonce string
	user string
	password string
}

func (cram *SaslCRAM) initialMessage(user, password string) (string, error) {
	nBytes := make([]byte, 15)
	rand.Read(nBytes)
	cram.client_nonce =  base64.StdEncoding.EncodeToString(nBytes)
	cram.password = password
	cram.user = user
	return fmt.Sprintf("n,,n=%s,r=%s", user, cram.client_nonce), nil

}

func (cram *SaslCRAM)challengeResponse(challenge string) (string, error) {
	var combinedNonce, salt, iterationCount string
	Hi := func (message string, salt string, iterations int) ([]byte, error) {
		byte_message := []byte(message)
		mac := hmac.New(cram.hash_func, byte_message)
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
			mac := hmac.New(cram.hash_func, byte_message)
			mac.Write(lastVal)
			newVal = mac.Sum([]byte{})
			for i := range rVal {
				rVal[i] ^= newVal[i]
			}
			lastVal = newVal
		}
		return rVal, nil
	}
	challengeFields := strings.Split(string(challenge), ",")
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
		return "", err
	}
	salted_password, err := Hi(cram.password, salt, int(i_count))
	if err != nil {
		return "", err
	}
	mac := hmac.New(cram.hash_func, salted_password)
	mac.Write([]byte("Client Key"))
	client_key := mac.Sum([]byte{})
	h_func := cram.hash_func()
	h_func.Write(client_key)
	stored_key := h_func.Sum([]byte{})
	auth_message := fmt.Sprintf("n=%s,r=%s,%s,c=biws,r=%s", cram.user, cram.client_nonce, string(challenge), combinedNonce)
	mac = hmac.New(cram.hash_func, stored_key)
	mac.Write([]byte(auth_message))
	client_sig := mac.Sum([]byte{})
	client_proof := client_key
	for i := range client_sig {
		client_proof[i] ^= client_sig[i]
	}

	if err != nil {
		return "", err
	}
	return fmt.Sprintf("c=biws,r=%s,p=%s", combinedNonce, base64.StdEncoding.EncodeToString(client_proof)), nil
}

func saslSendResponse(stream *Stream, response string) error {
	response_encoded := saslResponse{Text:  base64.StdEncoding.EncodeToString([]byte(response))}

	if err := stream.Send(&response_encoded); err != nil {
		return err
	}
	return nil
}
