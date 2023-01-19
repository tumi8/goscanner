package scans

import (
	"errors"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"golang.org/x/time/rate"
	"io"
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
	keyLogFile io.Writer
}

func (s *SCSVScan) GetDefaultPort() int {
	return 443
}

func (s *SCSVScan) Init(opts *misc.Options, keylogFile io.Writer) {
	s.keyLogFile = keylogFile
}

// ScanProtocol performs the actual TLS scan and adds results to the target
func (s *SCSVScan) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (net.Conn, error) {

	oldTlsConn, ok := conn.(*tls.Conn)

	if !ok {
		log.Panic().Msg("SCVS Scan needs an existing TLS connection. Please call scan after TLS scan")
	}
	tlsVersion := oldTlsConn.ConnectionState().Version

	connNew, synStart, synEnd, err := reconnect(conn, timeout)

	if err != nil {
		result.AddResult(results.ScanSubResult{
			SynStart: synStart,
			SynEnd:   synEnd,
			Result:   &results.SCSVResult{Err: err},
		})
		return connNew, err
	} else {
		// Use SCSV pseudo cipher with decreased TLS version
		tlsConn, err := scanTLS(conn, target.Domain, timeout, tlsVersion-1, nil, scsvCiphers, nil, target.CHName, s.keyLogFile, nil)

		if err != nil {
			// This is what should happen according to RFC 7507
			result.AddResult(results.ScanSubResult{SynStart: synStart, SynEnd: synEnd, ScanEnd: time.Now().UTC(), Result: &results.SCSVResult{Err: err}})
		} else {
			result.AddResult(results.ScanSubResult{
				SynStart: synStart,
				SynEnd:   synEnd,
				ScanEnd:  time.Now().UTC(),
				Result:   &results.SCSVResult{Version: tlsConn.ConnectionState().Version, Cipher: tlsConn.ConnectionState().CipherSuite, Err: errors.New("")},
			})
		}
		return tlsConn, nil

	}
}
