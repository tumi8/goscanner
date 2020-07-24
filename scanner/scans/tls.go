package scans

import (
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/tls"
	"net"
	"time"
)

type TLSScan struct {

}

func (s *TLSScan) GetDefaultPort() int {
	return 443
}

func (s *TLSScan) Init(opts *misc.Options)  {}

// ScanProtocol performs the actual TLS scan and adds results to the target
func (s *TLSScan) Scan(conn *net.Conn, target *Target, result *results.ScanResult,timeout time.Duration, synStart time.Time, synEnd time.Time) *net.Conn {
	serverName := target.Domain
	cache := tls.NewLRUClientSessionCache(1)
	tlsConn, err := scanTLS(conn, serverName, timeout, 0,  cache, nil)
	var tlsConnVar net.Conn
	tlsConnVar = tlsConn

	if err != nil {
		result.AddResult(results.ScanSubResult{synStart, synEnd, time.Now().UTC(), &results.TLSResult{Err: err}})
		return conn
	} else {

		tlsVersion := tlsConn.ConnectionState().Version
		result.AddResult(results.ScanSubResult{
			SynStart: synStart,
			SynEnd: synEnd,
			ScanEnd: time.Now().UTC(),
			Result: &results.TLSResult {
				tlsConn.ConnectionState().PeerCertificates,
				tlsVersion,
				tlsConn.ConnectionState().CipherSuite,
				err,
			},
		})

		for i, certificate := range tlsConn.ConnectionState().PeerCertificates {
			result.AddResult(results.ScanSubResult{
				SynStart: synStart,
				SynEnd:   synEnd,
				ScanEnd:  time.Now().UTC(),
				Result:   &results.CertResult {
					Depth: i,
					Cert:  certificate,
				},
			})
			result.AddResult(results.ScanSubResult{
				SynStart: synStart,
				SynEnd:   synEnd,
				ScanEnd:  time.Now().UTC(),
				Result:   &results.CertRelationResult {
					Depth: i,
					Cert:  certificate,
				},
			})
		}


		return &tlsConnVar
	}
}


func scanTLS(conn *net.Conn, serverName string, timeout time.Duration, maxVersion uint16, clientSessionCache tls.ClientSessionCache, ciphers []uint16) (*tls.Conn, error) {

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		// Use SNI if domain name is available
		ServerName: serverName,
		MaxVersion: maxVersion,
		// Use cache to speed up resumption for multiple HTTP requests
		ClientSessionCache: clientSessionCache,
	}
	if ciphers != nil {
		tlsConfig.CipherSuites = ciphers
	}

	// Establish TLS connection on top of TCP connection
	tlsConn := tls.Client(*conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	err := tlsConn.Handshake()
	return tlsConn, err
}

// reconnect reestablishes the TCP connection
func reconnect(conn *net.Conn, timeout time.Duration) (*net.Conn, time.Time, time.Time, error) {
	localAddr, _, _ := net.SplitHostPort((*conn).LocalAddr().String())
	ip := (*conn).RemoteAddr().String()
	// Close previous connection
	(*conn).Close()

	synStart := time.Now().UTC()
	dialer := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(localAddr)}}
	synEnd := time.Now().UTC()

	var newConn net.Conn
	newConn, err := dialer.Dial("tcp", ip)

	return &newConn, synStart, synEnd, err
}
