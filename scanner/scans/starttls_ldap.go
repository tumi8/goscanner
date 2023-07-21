package scans

import (
	"errors"
	ber "github.com/go-asn1-ber/asn1-ber"
	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"golang.org/x/time/rate"
	"io"
	"net"
	"strings"
	"time"
)

const (
	ldapStartTLSOID = "1.3.6.1.4.1.1466.20037"
)

type StartTLSLDAP struct {
	messageID  uint32
	keyLogFile io.Writer
}

func (s *StartTLSLDAP) Init(opts *misc.Options, keylogFile io.Writer) {
	s.keyLogFile = keylogFile
}

func (s *StartTLSLDAP) GetDefaultPort() int {
	return 636
}

func (s *StartTLSLDAP) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration,
	synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (rconn net.Conn, err error) {

	/* reconnect if you add starttls to another protocol;
	   in case your scanning pipeline contains multiple protocol scans */
	rconn, synStart, synEnd, err = reconnect(conn, timeout)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			// starttls connection must be finished so the next scans may succeed
			rconn, _, _, err = reconnect(rconn, timeout)
			if err != nil {
				rconn = nil // could not reconnect, then stopping
			}
		}
	}()

	packet := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "LDAP Request")
	packet.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, s.nextMessageID(), "MessageID"))
	request := ber.Encode(ber.ClassApplication, ber.TypeConstructed, ldap.ApplicationExtendedRequest, nil, "Start TLS")
	request.AppendChild(ber.NewString(ber.ClassContext, ber.TypePrimitive, 0, ldapStartTLSOID, "TLS Extended Command"))
	packet.AppendChild(request)
	log.Debug().Str("requestPacket", packet.Data.String()).Msg("Send request")

	_, err = rconn.Write(packet.Bytes())
	sTlsLdapResult := results.LDAPResult{HasStartTLS: false}
	if err != nil {
		addResult(result, synStart, synEnd, err, &sTlsLdapResult)
		return rconn, err
	}

	var packetResponse []byte
	packetResponse = make([]byte, 1024) // typical right response is the ldapStartTLSOID, rfc4511#section-4.14.2
	_, err = rconn.Read(packetResponse)
	if err != nil {
		addResult(result, synStart, synEnd, err, &sTlsLdapResult)
		return rconn, err
	}

	packet = ber.DecodePacket(packetResponse)
	log.Debug().Str("responsePacket", packet.Data.String()).Msg("Got response")
	err = ldap.GetLDAPError(packet)
	if err != nil {
		addResult(result, synStart, synEnd, err, &sTlsLdapResult)
		return rconn, err
	}

	if err = hasLDAPStartTLSOID(packet); err != nil {
		addResult(result, synStart, synEnd, err, &sTlsLdapResult)
		return rconn, err
	}

	sTlsLdapResult.HasStartTLS = true
	addResult(result, synStart, synEnd, nil, &sTlsLdapResult)
	return rconn, nil
}

func hasLDAPStartTLSOID(packet *ber.Packet) error {
	if len(packet.Children) >= 2 && strings.Contains(packet.Children[1].Data.String(), ldapStartTLSOID) {
		return nil
	}
	return errors.New("the server did not responded with StartTLS")
}

func (s *StartTLSLDAP) nextMessageID() uint32 {
	s.messageID++
	if s.messageID == 0 {
		// avoid overflow of messageID and return 0 (see rfc4511#section-4.1.1.1 for messageID = 0)
		s.messageID++
	}
	return s.messageID
}

func addResult(result *results.ScanResult, synStart time.Time, synEnd time.Time, err error, ldapResult *results.LDAPResult) {
	ldapResult.LdapError = err
	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result:   ldapResult,
	})
}
