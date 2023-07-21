package results

import (
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/tls"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var hostCsvHeader = []string{"id", "ip", "port", "server_name", "synStart", "synEnd", "scanEnd", "protocol", "cipher", "resultString", "error_data", "cert_id", "cert_hash", "pub_key_hash", "cert_valid", "tls_alerts_send", "peer_certificates", "tls_alerts_received", "client_hello"}
var skippedErrors = [...]string{"TIMEOUT", "CONNECTION REFUSED", "NO ROUTE", "NETWORK UNREACHABLE"}
var timeDiff time.Duration

type TLSResult struct {
	Certificate     *x509.Certificate
	AllCertificates []*x509.Certificate
	Version         uint16
	Cipher          uint16
	SendAlerts      []tls.Alert
	RecvAlerts      []tls.Alert
	Err             error
	Errors          []error
}

func init() {
	timeDiff = misc.GetNtpLocalTimeDiff()
}

func (t *TLSResult) GetCsvFileName() string {
	return FileHosts
}

func (t *TLSResult) GetCsvHeader() []string {
	return hostCsvHeader
}

func (t *TLSResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.Err(err).Str("address", parentResult.Address).Msg("Could not split address into host and port parts.")
	}

	resultString := "SUCCESS"
	var handshakeErrors []string
	if t.Err != nil {
		handshakeErrors = append(handshakeErrors, t.Err.Error())
		resultString = HandshakeErrorLookup(t.Err)
		if skipErrors {
			for _, e := range skippedErrors {
				if resultString == e {
					return nil
				}
			}
		}
	}

	// Check protocol and cipher
	protocol := strconv.Itoa(int(t.Version))
	cipher := strconv.FormatUint(uint64(t.Cipher), 16)

	var scanEndStr string
	if scanEnd.Unix() > 0 {
		scanEndStr = strconv.FormatInt(scanEnd.Add(timeDiff).Unix(), 10)
	}

	idCert := ""
	sha256Hex := ""
	leafSHA256SPKI := ""

	if t.Certificate != nil {
		sha256Hex = hex.EncodeToString(misc.GetSHA256(t.Certificate.Raw))
		idCertUInt, _ := certCache.GetID(t.Certificate)
		idCert = strconv.FormatUint(uint64(idCertUInt), 10)
		leafSHA256SPKI = hex.EncodeToString(misc.GetSHA256(t.Certificate.RawSubjectPublicKeyInfo))
	}

	var peerCertificates []int
	if t.AllCertificates != nil {
		for _, cert := range t.AllCertificates {
			id, _ := certCache.GetID(cert)
			peerCertificates = append(peerCertificates, int(id))
		}
	}

	var certValid *bool

	sendAlerts := make([]int, len(t.SendAlerts))
	for i, alert := range t.SendAlerts {
		if alert.GetCode() == 42 {
			certValid = misc.NewFalse()
		}
		sendAlerts[i] = int(alert.GetCode())
	}
	if len(t.Errors) > 0 {
		for _, err := range t.Errors {
			handshakeErrors = append(handshakeErrors, err.Error())
			if strings.Contains(err.Error(), "invalid signature") {
				certValid = misc.NewFalse()
			}
		}
	}

	if certValid == nil && t.Err == nil {
		certValid = misc.NewTrue()
	}
	recvAlerts := make([]int, len(t.RecvAlerts))
	for i, alert := range t.RecvAlerts {
		recvAlerts[i] = int(alert.GetCode())
	}

	// Write row in host CSV file
	// [host, port, server_name, synStart, synEnd, scanEnd, protocol, cipher, result, error_data, cert_hash, cert_valid, pub_key_hash]
	return writer.Write([]string{
		parentResult.Id.ToString(),
		ip,
		port,
		parentResult.Domain,
		strconv.FormatInt(synStart.Add(timeDiff).Unix(), 10),
		strconv.FormatInt(synEnd.Add(timeDiff).Unix(), 10),
		scanEndStr,
		protocol,
		cipher,
		resultString,
		misc.ToJSONArray(handshakeErrors),
		idCert,
		sha256Hex,
		leafSHA256SPKI,
		misc.ToCompactBinary(certValid),
		misc.ToJSONIntArray(sendAlerts),
		misc.ToJSONIntArray(peerCertificates),
		misc.ToJSONIntArray(recvAlerts),
		parentResult.CHName,
	})
}

// HandshakeErrorLookup returns a string for a certain handshake error
func HandshakeErrorLookup(err error) string {
	handshakeError := err.Error()
	var result string
	if m, _ := regexp.MatchString("timeout", handshakeError); m {
		result = "TIMEOUT"
	} else if m, _ := regexp.MatchString("connection refused", handshakeError); m {
		result = "CONNECTION REFUSED"
	} else if m, _ := regexp.MatchString("connection reset by peer", handshakeError); m {
		result = "CONNECTION RESET BY PEER"
	} else if m, _ := regexp.MatchString("no route to host", handshakeError); m {
		result = "NO ROUTE"
	} else if m, _ := regexp.MatchString("network is unreachable", handshakeError); m {
		result = "NETWORK UNREACHABLE"
	} else if m, _ := regexp.MatchString("unknown protcol", handshakeError); m {
		result = "UNKNOWN PROTOCOL"
	} else if m, _ := regexp.MatchString("protocol version", handshakeError); m {
		result = "UNKNOWN PROTOCOL"
	} else if m, _ := regexp.MatchString("tls: oversized record received with length", handshakeError); m {
		result = "OVERSIZED RECORD"
	} else if m, _ := regexp.MatchString("tls", handshakeError); m {
		result = "SSL HANDSHAKE FAILURE"
	} else if m, _ := regexp.MatchString("handshake failure", handshakeError); m {
		result = "SSL HANDSHAKE FAILURE"
	} else {
		result = "OTHER FAILURE"
	}
	return result
}
