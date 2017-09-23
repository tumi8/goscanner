package scanner

import (
	"bufio"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tumi8/tls"
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

// TLSScanner implements the scanning of the TLS protocol
type TLSScanner struct {
	inputChan    chan *Target
	outputChan   chan *Target
	doHTTP       bool
	HTTPHeaders  []string
	HTTPRequests []string
	doSCSV       bool
}

// NewTLSScanner returns an initialized TLSScanner struct
func NewTLSScanner(httpHeaders string, httpRequests []string, doSCSV bool) TLSScanner {

	doHTTP := httpHeaders != "" || len(httpRequests) != 0
	headerList := strings.Split(httpHeaders, ",")

	// Execute HEAD request on root path by default
	if doHTTP && len(httpRequests) == 0 {
		httpRequests = []string{"HEAD,/"}
	}

	// Create channels for input and output targets
	return TLSScanner{make(chan *Target, 10000), make(chan *Target), doHTTP, headerList, httpRequests, doSCSV}
}

func scanTLS(conn net.Conn, serverName string, timeout time.Duration, maxVersion uint16, scsv bool) (*tls.Conn, error) {

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		// Use SNI if domain name is available
		ServerName: serverName,
		MaxVersion: maxVersion,
	}
	if scsv {
		tlsConfig.CipherSuites = scsvCiphers
	}

	// Establish TLS connection on top of TCP connection
	tlsConn := tls.Client(conn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(timeout))
	err := tlsConn.Handshake()

	return tlsConn, err
}

// ScanProtocol performs the actual TLS scan and adds results to the target
func (s TLSScanner) ScanProtocol(conn net.Conn, host *Target, timeout time.Duration, synStart time.Time, synEnd time.Time) {

	serverName := (*host).Domains()[0]
	tlsConn, err := scanTLS(conn, serverName, timeout, 0, false)

	if err != nil {
		(*host).AddResult(conn.RemoteAddr().String(), &ScanResult{synStart, synEnd, time.Now().UTC(), err})
	} else {
		(*host).AddResult(conn.RemoteAddr().String(), &ScanResult{synStart, synEnd, time.Now().UTC(), TLSResult{tlsConn.ConnectionState().PeerCertificates, tlsConn.ConnectionState().Version, tlsConn.ConnectionState().CipherSuite, err}})

		if s.doHTTP {

			for _, req := range s.HTTPRequests {
				var httpCode int
				var headersStr string

				reqSplit := strings.SplitN(req, ",", 2)
				method, path := reqSplit[0], reqSplit[1]

				httpCode, httpHeaders, err := getHTTPHeaders(tlsConn, serverName, method, path)

				for _, key := range s.HTTPHeaders {
					value := httpHeaders.Get(key)
					if value != "" {
						headersStr += key + ": " + value + "\n"
					}
				}
				headersStr = strings.TrimRight(headersStr, "\n")

				// Add HTTP result
				(*host).AddResult(conn.RemoteAddr().String(), &ScanResult{synStart, synEnd, time.Now().UTC(), HTTPResult{method, path, httpCode, headersStr, err}})
			}
		}

		if s.doSCSV {

			localAddr, _, _ := net.SplitHostPort(conn.LocalAddr().String())
			ip := conn.RemoteAddr().String()
			version := tlsConn.ConnectionState().Version
			// Close previous connection
			conn.Close()

			synStart := time.Now().UTC()
			dialer := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(localAddr)}}
			synEnd := time.Now().UTC()

			conn, err = dialer.Dial("tcp", ip)
			if err != nil {
				(*host).AddResult(ip, &ScanResult{synStart, synEnd, time.Time{}, SCSVResult{0, 0, err}})
			} else {

				// Use SCSV pseudo cipher with decreased TLS version
				tlsConn, err = scanTLS(conn, serverName, timeout, version-1, true)

				if err != nil {
					// This is what should happen according to RFC 7507
					(*host).AddResult(ip, &ScanResult{synStart, synEnd, time.Now().UTC(), SCSVResult{0, 0, err}})
				} else {
					(*host).AddResult(ip, &ScanResult{synStart, synEnd, time.Now().UTC(), SCSVResult{tlsConn.ConnectionState().Version, tlsConn.ConnectionState().CipherSuite, errors.New("")}})
				}

				conn.Close()
			}
		}
	}
}

// getHTTPHeaders sends a HTTP request and returns HTTP headers
func getHTTPHeaders(tlsConn *tls.Conn, serverName string, method string, path string) (int, http.Header, error) {

	req, err := http.NewRequest(method, "https://"+serverName+path, nil)
	if err != nil {
		return -1, nil, err
	}

	// Mimick Google Chrome
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36")
	req.Header.Add("Host", serverName)

	if err := req.Write(tlsConn); err != nil {
		return -1, nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(tlsConn), req)
	if err != nil {
		return -1, nil, err
	}
	// Close response in order to make additional requests
	resp.Body.Close()

	return resp.StatusCode, resp.Header, nil
}

// InputChannel returns the input channel for reading and writing targets
func (s TLSScanner) InputChannel() chan *Target {
	return s.inputChan
}

// OutputChannel returns the output channel for reading and writing resutls
func (s TLSScanner) OutputChannel() chan *Target {
	return s.outputChan
}
