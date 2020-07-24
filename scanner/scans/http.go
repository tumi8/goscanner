package scans

import (
	"bufio"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/tls"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type HTTPScan struct {
	HTTPHeaders  []string
	HTTPRequests []string
}

func (s *HTTPScan) GetDefaultPort() int {
	return 80
}

func (s *HTTPScan) Init(opts *misc.Options)  {
	s.HTTPHeaders = strings.Split(opts.HTTPHeaders, ",")
	s.HTTPRequests = opts.HTTPRequests

	// Execute HEAD request on root path by default
	if len(s.HTTPRequests) == 0 {
		s.HTTPRequests = []string{"HEAD,/"}
	}

}


func (s *HTTPScan) Scan(conn *net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time) *net.Conn {

	cache := tls.NewLRUClientSessionCache(1)

	for _, req := range s.HTTPRequests {
		var httpCode int
		var httpHeaders http.Header
		var headersStr string
		var err error

		reqSplit := strings.SplitN(req, ",", 2)
		method, path := reqSplit[0], reqSplit[1]

		httpCode, httpHeaders, err = s.getHTTPHeaders(conn, target.Domain, method, path)

		// Establish new TCP connection and try to resume the TLS connection
		if err == io.ErrUnexpectedEOF {
			conn, _, _, err = reconnect(conn, timeout)
			if err == nil {
				var newConn net.Conn
				newConn, err = scanTLS(conn, target.Domain, timeout, 0, cache, nil)
				conn = &newConn
				httpCode, httpHeaders, err = s.getHTTPHeaders(conn, target.Domain, method, path)
			}
		}

		for _, key := range s.HTTPHeaders {
			value := httpHeaders.Get(key)
			if value != "" {
				headersStr += key + ": " + value + "\n"
			}
		}
		headersStr = strings.TrimRight(headersStr, "\n")

		// Add HTTP result
		result.AddResult(results.ScanSubResult{synStart, synEnd, time.Now().UTC(), &results.HTTPResult{method, path, httpCode, headersStr, err}})
	}
	return conn
}

// getHTTPHeaders sends a HTTP request and returns HTTP headers
func (s *HTTPScan) getHTTPHeaders(conn *net.Conn, serverName string, method string, path string) (int, http.Header, error) {

	req, err := http.NewRequest(method, "https://"+serverName+path, nil)
	if err != nil {
		return -1, nil, err
	}

	// Mimick Google Chrome
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/40.0.2214.85 Safari/537.36")
	req.Header.Add("Host", serverName)

	if err := req.Write(*conn); err != nil {
		return -1, nil, err
	}

	resp, err := http.ReadResponse(bufio.NewReader(*conn), req)
	if err != nil {
		return -1, nil, err
	}
	// Close response in order to make additional requests
	resp.Body.Close()

	return resp.StatusCode, resp.Header, nil
}