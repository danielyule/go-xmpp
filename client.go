package xmpp

import (
	"crypto/tls"
	"encoding/xml"
	"errors"
	"fmt"
	"log"
	"time"
)

// Config structure used to create a new XMPP client connection.
type ClientConfig struct {
	// Don't upgrade the connection to TLS, even if the server supports it. If
	// the server *requires* TLS then this option is ignored.
	NoTLS bool

	// Skip verification of the server's certificate chain. Probably only
	// useful during development.
	InsecureSkipVerify bool

	//Attempt in band registration if the server supports it
	RegisterUser bool
}

// Create a client XMPP over the stream.
func NewClientXMPP(stream *Stream, jid JID, password string, config *ClientConfig) (*XMPP, error) {

	if config == nil {
		config = &ClientConfig{}
	}

	for {

		if err := startClient(stream, jid); err != nil {
			return nil, err
		}

		// Read features.
		f := new(features)
		if err := stream.Decode(f, nil); err != nil {
			return nil, err
		}

		// TLS?
		if f.StartTLS != nil && (f.StartTLS.Required != nil || !config.NoTLS) {
			log.Println("Start TLS")
			if err := startTLS(stream, config); err != nil {
				return nil, err
			}
			continue // Restart
		}

		if config.RegisterUser {
			registerWithServer(stream, jid, password)
		}

		// Authentication
		if f.Mechanisms != nil {
			log.Println("Authenticating")
			if err := authenticate(stream, f.Mechanisms.Mechanisms, jid.Node, password); err != nil {
				return nil, err
			}
			continue // Restart
		}

		// Bind resource.
		if f.Bind != nil {
			log.Println("Binding resource.")
			boundJID, err := bindResource(stream, jid)
			if err != nil {
				return nil, err
			}
			jid = boundJID
		}

		// Session.
		if f.Session != nil {
			log.Println("Establishing session.")
			if err := establishSession(stream, jid.Domain); err != nil {
				return nil, err
			}
		}

		break
	}

	return newXMPP(jid, stream), nil
}

func startClient(stream *Stream, jid JID) error {

	start := xml.StartElement{
		xml.Name{"stream", "stream"},
		[]xml.Attr{
			xml.Attr{xml.Name{"", "xmlns"}, nsClient},
			xml.Attr{xml.Name{"xmlns", "stream"}, nsStreams},
			xml.Attr{xml.Name{"", "from"}, jid.Full()},
			xml.Attr{xml.Name{"", "to"}, jid.Domain},
			xml.Attr{xml.Name{"", "version"}, "1.0"},
		},
	}

	if rstart, err := stream.SendStart(&start); err != nil {
		return err
	} else {
		if rstart.Name != (xml.Name{nsStreams, "stream"}) {
			return fmt.Errorf("unexpected start element: %s", rstart.Name)
		}
	}

	return nil
}

func startTLS(stream *Stream, config *ClientConfig) error {

	if err := stream.Send(&tlsStart{}); err != nil {
		return err
	}

	p := tlsProceed{}
	if err := stream.Decode(&p, nil); err != nil {
		return err
	}

	tlsConfig := tls.Config{InsecureSkipVerify: config.InsecureSkipVerify}
	return stream.UpgradeTLS(&tlsConfig)
}

type tlsStart struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls starttls"`
}

type tlsProceed struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-tls proceed"`
}

func registerWithServer(stream *Stream, jid JID, password string) error {

	req := Iq{Id: UUID4(), Type: "get"}
	req.PayloadEncode(registerIqRequest{Username: jid.Node, Password: password})
	if err := stream.Send(req); err != nil {
		return err
	}
	resp := Iq{}
	err := stream.Decode(&resp, nil)
	if err != nil {
		return err
	}
	regResp := registerIqFields{}
	resp.PayloadDecode(&regResp)
	if regResp.Registered.Local != "" {
		//We're already registered on this server
		return nil
	}

	if regResp.Username.Local == "" ||   regResp.Password.Local == ""{
		return fmt.Errorf("Server did not allow for specification of username and password")
	}
	req = Iq{Id: req.Id, Type: "set"}
	registerReq := registerIqRequest{Username: jid.Node, Password: password}
	fillInRegistraionResponse(regResp, &registerReq)
	req.PayloadEncode(registerReq)
	if err := stream.Send(req); err != nil {
		return err
	}
	resp = Iq{}
	err = stream.Decode(&resp, nil)
	if err != nil {
		return err
	}
	return nil
}

func fillInRegistraionResponse(fields registerIqFields, response *registerIqRequest) {
	is_empty := func(name xml.Name) bool {
		return name.Local == ""
	}

	switch false {
	case is_empty(fields.Address):
		response.Address = "N/A"
	case is_empty(fields.City):
		response.City = "N/A"
	case is_empty(fields.Date):
		response.Date = time.Now().String()
	case is_empty(fields.Email):
		response.Email = "none@none"
	case is_empty(fields.First):
		response.First = "N/A"
	case is_empty(fields.Key):
		response.Key = "N/A"
	case is_empty(fields.Last):
		response.Last = "N/A"
	case is_empty(fields.Misc):
		response.Misc = "N/A"
	case is_empty(fields.Nick):
		response.Nick = "N/A"
	case is_empty(fields.Name):
		response.Name = "N/A"
	case is_empty(fields.Phone):
		response.Phone = "N/A"
	case is_empty(fields.State):
		response.State = "N/A"
	case is_empty(fields.Text):
		response.Text = "N/A"
	case is_empty(fields.Url):
		response.Text = "N/A"
	case is_empty(fields.Zip):
		response.Text = "N/A"

	}

}

type registerIqFields struct {
	XMLName  xml.Name `xml:"jabber:iq:register query"`
	Username xml.Name `xml:"username,omitempty"`
	Password xml.Name `xml:"password,omitempty"`
	Nick     xml.Name `xml:"nick,omitempty"`
	Name     xml.Name `xml:"name,omitempty"`
	First    xml.Name `xml:"first,omitempty"`
	Last     xml.Name `xml:"last,omitempty"`
	Email    xml.Name `xml:"email,omitempty"`
	Address  xml.Name `xml:"address,omitempty"`
	City     xml.Name `xml:"city,omitempty"`
	State    xml.Name `xml:"state,omitempty"`
	Zip      xml.Name `xml:"zip,omitempty"`
	Phone    xml.Name `xml:"phone,omitempty"`
	Url      xml.Name `xml:"url,omitempty"`
	Date     xml.Name `xml:"date,omitempty"`
	Misc     xml.Name `xml:"misc,omitempty"`
	Text     xml.Name `xml:"text,omitempty"`
	Key      xml.Name `xml:"key,omitempty"`
	Registered xml.Name `xml:"registered,omitempty"`
}

type registerIqRequest struct {
	XMLName  xml.Name `xml:"jabber:iq:register query"`
	Username string `xml:"username,omitempty"`
	Password string `xml:"password,omitempty"`
	Nick     string `xml:"nick,omitempty"`
	Name     string `xml:"name,omitempty"`
	First    string `xml:"first,omitempty"`
	Last     string `xml:"last,omitempty"`
	Email    string `xml:"email,omitempty"`
	Address  string `xml:"address,omitempty"`
	City     string `xml:"city,omitempty"`
	State    string `xml:"state,omitempty"`
	Zip      string `xml:"zip,omitempty"`
	Phone    string `xml:"phone,omitempty"`
	Url      string `xml:"url,omitempty"`
	Date     string `xml:"date,omitempty"`
	Misc     string `xml:"misc,omitempty"`
	Text     string `xml:"text,omitempty"`
	Key      string `xml:"key,omitempty"`
}

func authenticate(stream *Stream, mechanisms []string, user, password string) error {
	for _, handler := range authHandlers {
		if !stringSliceContains(mechanisms, handler.Mechanism) {
			continue
		}
		if err := handler.Fn(stream, user, password); err == nil {
			log.Printf("Authentication (%s) successful", handler.Mechanism)
			return nil
		}
	}
	return errors.New("No supported SASL mechanism found.")
}

type authHandler struct {
	Mechanism string
	Fn        func(*Stream, string, string) error
}

var authHandlers = []authHandler{
	{"PLAIN", authenticatePlain},
}

func authenticatePlain(stream *Stream, user, password string) error {
	auth := saslAuth{Mechanism: "PLAIN", Text: saslEncodePlain(user, password)}
	if err := stream.Send(&auth); err != nil {
		return err
	}
	return authenticateResponse(stream)
}

func authenticateResponse(stream *Stream) error {
	if se, err := stream.Next(); err != nil {
		return err
	} else {
		switch se.Name.Local {
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
	panic("unreachable")
}

type saslAuth struct {
	XMLName   xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl auth"`
	Mechanism string   `xml:"mechanism,attr"`
	Text      string   `xml:",chardata"`
}

func bindResource(stream *Stream, jid JID) (JID, error) {

	req := Iq{Id: UUID4(), Type: "set"}
	if jid.Resource == "" {
		req.PayloadEncode(bindIq{})
	} else {
		req.PayloadEncode(bindIq{Resource: jid.Resource})
	}
	if err := stream.Send(req); err != nil {
		return JID{}, err
	}

	resp := Iq{}
	err := stream.Decode(&resp, nil)
	if err != nil {
		return JID{}, err
	}
	bindResp := bindIq{}
	resp.PayloadDecode(&bindResp)

	boundJID, err := ParseJID(bindResp.JID)
	return boundJID, nil
}

type bindIq struct {
	XMLName  xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
	Resource string   `xml:"resource,omitempty"`
	JID      string   `xml:"jid,omitempty"`
}

func establishSession(stream *Stream, domain string) error {

	req := Iq{Id: UUID4(), Type: "set", To: domain}
	req.PayloadEncode(&session{})
	if err := stream.Send(req); err != nil {
		return err
	}

	resp := Iq{}
	if err := stream.Decode(&resp, nil); err != nil {
		return err
	} else if resp.Error != nil {
		return resp.Error
	}

	return nil
}

func stringSliceContains(l []string, m string) bool {
	for _, i := range l {
		if i == m {
			return true
		}
	}
	return false
}

type features struct {
	XMLName    xml.Name     `xml:"http://etherx.jabber.org/streams features"`
	StartTLS   *tlsStartTLS `xml:"starttls"`
	Mechanisms *mechanisms  `xml:"mechanisms"`
	Bind       *bind        `xml:"bind"`
	Session    *session     `xml:"session"`
}

type session struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-session session"`
}

type bind struct {
	XMLName  xml.Name  `xml:"urn:ietf:params:xml:ns:xmpp-bind bind"`
	Required *required `xml:"required"`
}

type mechanisms struct {
	XMLName    xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl mechanisms"`
	Mechanisms []string `xml:"mechanism"`
}

type tlsStartTLS struct {
	XMLName  xml.Name  `xml:"urn:ietf:params:xml:ns:xmpp-tls starttls"`
	Required *required `xml:"required"`
}

type required struct{}

type saslFailure struct {
	XMLName xml.Name `xml:"urn:ietf:params:xml:ns:xmpp-sasl failure"`
	Reason  xml.Name `xml:",any"`
}

// BUG(matt): authentication incorrectly reports, "No supported SASL mechanism
// found", for authentication attemtps that fail due to invalid credentials.
