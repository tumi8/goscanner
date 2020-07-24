package results

import (
	"crypto/x509"
	"encoding/csv"
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/tumi8/goscanner/scanner/misc"
	"net"
	"regexp"
	"strconv"
	"time"
)

var hostCsvHeader = []string{"host", "rtt", "port", "server_name", "synStart", "synEnd", "scanEnd", "protocol", "cipher", "resultString", "verify_err_no", "verify_code", "server_version", "depth", "depth_verbose", "error_data"}
var skippedErrors = [...]string{"TIMEOUT", "CONNECTION REFUSED", "NO ROUTE", "NETWORK UNREACHABLE"}
var cipherSuites map[uint16]string
var timeDiff time.Duration

type TLSResult struct {
	Certificates []*x509.Certificate
	Version      uint16
	Cipher       uint16
	Err          error
}

func init() {
	cipherSuites = misc.ReadCiphersFromAsset()
	timeDiff = misc.GetNtpLocalTimeDiff()
}

func (t *TLSResult) GetCsvFileName() string {
	return FileHosts
}

func (t *TLSResult) GetCsvHeader() []string {
	return hostCsvHeader
}

func (t *TLSResult)  WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool,  cacheFunc func([]byte) []byte, cache map[string]map[string]struct{}) {
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.WithFields(log.Fields{
			"address": parentResult.Address,
		}).Error("Could not split address into host and port parts.")
	}

	resultString := "SUCCESS"
	handshakeError := errors.New("")
	if t.Err != nil {
		handshakeError = t.Err
		resultString = HandshakeErrorLookup(t.Err)
		if skipErrors {
			for _, e := range skippedErrors {
				if resultString == e {
					return
				}
			}
		}
	}

	var protocol, cipher string
	var ok bool

	// Check protocol and cipher
	if protocol, ok = cipherSuites[t.Version]; !ok {
		protocol = "not set: " + strconv.Itoa(int(t.Version))
	}
	if cipher, ok = cipherSuites[t.Cipher]; !ok {
		cipher = "unknown: " + strconv.Itoa(int(t.Cipher))
	}

	var scanEndStr string
	if scanEnd.Unix() > 0 {
		scanEndStr = strconv.FormatInt(scanEnd.Add(timeDiff).Unix(), 10)
	}

	// Write row in host CSV file
	// [host, rtt, port, server_name, synStart, synEnd, scanEnd, protocol, cipher, result, verify_err_no, verify_code, server_version, depth, depth_verbose, error_data]
	if ok := writer.Write([]string{ip, "", port, parentResult.Domain, strconv.FormatInt(synStart.Add(timeDiff).Unix(), 10), strconv.FormatInt(synEnd.Add(timeDiff).Unix(), 10), scanEndStr, protocol, cipher, resultString, "", "", "", "", "", handshakeError.Error()}); ok != nil {
		log.WithFields(log.Fields{
			"file": parentResult.Address,
		}).Error("Error writing to host file")
	}
}

// handshakeErrorLookup returns a string for a certain handshake error
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

