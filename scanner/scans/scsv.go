package scans

import (
	"errors"
	log "github.com/sirupsen/logrus"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/tls"
	"net"
	"time"
)

var scsvCiphers = []uint16{
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,   // for TLS < 1.2
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA, // for TLS < 1.2
	tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,   // for TLS < 1.2
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA, // for TLS < 1.2
	tls.TLS_FALLBACK_SCSV,
}

type SCSVScan struct {
}

func (s *SCSVScan) GetDefaultPort() int {
	return 443
}

func (s *SCSVScan) Init(opts *misc.Options)  {}

// ScanProtocol performs the actual TLS scan and adds results to the target
func (s *SCSVScan) Scan(connOld *net.Conn, target *Target, result *results.ScanResult,timeout time.Duration, synStart time.Time, synEnd time.Time) *net.Conn {

	oldTlsConn, ok := (*connOld).(*tls.Conn)

	if !ok {
		log.Errorln("SCVS Scan needs an existing TLS connection. Please call scan after TLS scan")
		return  connOld
	}
	tlsVersion := oldTlsConn.ConnectionState().Version

	var newConn net.Conn
	conn, synStart, synEnd, err := reconnect(connOld, timeout)

	if err != nil {
		result.AddResult(results.ScanSubResult{synStart, synEnd, time.Time{}, &results.SCSVResult{0, 0, err}})
		newConn = *conn
	} else {

		// Use SCSV pseudo cipher with decreased TLS version
		tlsConn, err := scanTLS(conn, target.Domain, timeout, tlsVersion-1, nil, scsvCiphers)

		if err != nil {
			// This is what should happen according to RFC 7507
			result.AddResult(results.ScanSubResult{synStart, synEnd, time.Now().UTC(), &results.SCSVResult{0, 0, err}})
		} else {
			result.AddResult(results.ScanSubResult{synStart, synEnd, time.Now().UTC(), &results.SCSVResult{tlsConn.ConnectionState().Version, tlsConn.ConnectionState().CipherSuite, errors.New("")}})
		}
		newConn = tlsConn
	}
	return &newConn
}
