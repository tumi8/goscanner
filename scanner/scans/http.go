package scans

import (
	"bufio"
	"context"
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"golang.org/x/net/http2"
	"io"
	"net"
	"net/http"
	"strings"
	"time"
)

type HTTPRequest struct {
	method string
	path   string
}

type HTTPScan struct {
	HTTPHeaders  []string
	HTTPRequests []HTTPRequest
	Verbose      bool
	keyLogFile   io.Writer
}

func (s *HTTPScan) GetDefaultPort() int {
	return 80
}

func (s *HTTPScan) Init(opts *misc.Options, keylogFile io.Writer) {
	s.HTTPHeaders = strings.Split(opts.HTTPHeaders, ",")

	for _, header := range s.HTTPHeaders {
		results.HttpCsvHeader = append(results.HttpCsvHeader, header)
	}

	for _, req := range opts.HTTPRequests {
		reqSplit := strings.SplitN(req, ",", 2)
		method, path := reqSplit[0], reqSplit[1]
		s.HTTPRequests = append(s.HTTPRequests, HTTPRequest{method, path})
	}

	// Execute HEAD request on root path by default
	if len(s.HTTPRequests) == 0 {
		s.HTTPRequests = []HTTPRequest{HTTPRequest{"HEAD", "/"}}
	}

	s.Verbose = opts.HTTPExtendedExport

	s.keyLogFile = keylogFile
}

func (s *HTTPScan) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time) (net.Conn, error) {

	cache := tls.NewLRUClientSessionCache(1)

	var connError error

	for _, req := range s.HTTPRequests {
		var httpCode int
		var httpHeaders http.Header
		var headers []string
		var httpHostName string
		var protocol string
		var err error

		if target.Domain != "" {
			httpHostName = target.Domain
		} else {
			httpHostName = target.Ip
		}

		httpCode, httpHeaders, protocol, err = s.getHTTPHeaders(conn, httpHostName, req.method, req.path, timeout)

		// Establish new TCP connection and try to resume the TLS connection
		if err == io.ErrUnexpectedEOF {
			conn, _, _, err = reconnect(conn, timeout)
			if err == nil {
				conn, err = scanTLS(conn, target.Domain, timeout, 0, cache, nil, nil, target.CHName, s.keyLogFile)
				if err != nil {
					connError = s.processError(err, req.method, req.path, "Error during tcp reconnect for http headers", result, synStart, synEnd)
					continue
				} else {
					httpCode, httpHeaders, protocol, err = s.getHTTPHeaders(conn, httpHostName, req.method, req.path, timeout)
					if err != nil {
						connError = s.processError(err, req.method, req.path, "Error during 2nd request for http headers", result, synStart, synEnd)
						continue
					}
				}
			}
		} else if err != nil {
			connError = s.processError(err, req.method, req.path, "Error during request for http headers", result, synStart, synEnd)
			continue
		}

		for _, key := range s.HTTPHeaders {
			value := httpHeaders.Get(key)
			if value != "" {
				headers = append(headers, value)
			} else {
				headers = append(headers, "")
			}
		}

		if s.Verbose {
			pos := 0
			for key, values := range httpHeaders {
				if len(values) == 0 {
					values = []string{""}
				}
				for i := range values {
					result.AddResult(results.ScanSubResult{
						SynStart: synStart,
						SynEnd:   synEnd,
						ScanEnd:  time.Now().UTC(),
						Result: &results.HTTPExtendedResult{
							Header:   key,
							Position: pos,
							Content:  values[i],
						},
					})
					pos++
				}

			}
		}

		// Add HTTP result
		result.AddResult(results.ScanSubResult{
			SynStart: synStart,
			SynEnd:   synEnd,
			ScanEnd:  time.Now().UTC(),
			Result: &results.HTTPResult{
				Protocol:    protocol,
				HttpMethod:  req.method,
				HttpPath:    req.path,
				HttpCode:    httpCode,
				HttpHeaders: headers,
				HttpError:   err},
		})
	}
	return conn, connError
}

func (s *HTTPScan) processError(err error, method string, path string, message string, result *results.ScanResult, synStart time.Time, synEnd time.Time) error {
	err = errors.Wrap(err, message)

	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result: &results.HTTPResult{
			HttpMethod: method,
			HttpPath:   path,
			HttpError:  err},
	})

	return err
}

type SingleConnPool struct {
	t     *http2.Transport
	cConn *http2.ClientConn
}

func (uc SingleConnPool) GetClientConn(_ *http.Request, _ string) (*http2.ClientConn, error) {
	return uc.cConn, nil
}
func (uc SingleConnPool) MarkDead(_ *http2.ClientConn) {}

// getHTTPHeaders sends a HTTP request and returns HTTP headers
func (s *HTTPScan) getHTTPHeaders(conn net.Conn, serverName string, method string, path string, timeout time.Duration) (int, http.Header, string, error) {

	tlsConn, isTls := conn.(*tls.Conn)
	isHttp2 := false
	if isTls {
		isHttp2 = tlsConn.ConnectionState().NegotiatedProtocol == "h2"
	}

	ctx, cancelContext := context.WithTimeout(context.Background(), timeout)
	defer cancelContext()

	req, err := http.NewRequestWithContext(ctx, method, "https://"+serverName+path, nil)
	if err != nil {
		return -1, nil, "", err
	}

	// Mimic Google Chrome
	req.Header.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.146 Safari/537.36")
	req.Header.Add("Host", serverName)

	var resp *http.Response
	if isHttp2 {
		tp := http2.Transport{}
		cConn, err := tp.NewClientConn(tlsConn)
		if err != nil {
			if misc.IsClosedConnErr(err) {
				return -1, nil, "", io.ErrUnexpectedEOF
			}
			log.Err(err).Msg("Error creating client conn")
			return -1, nil, "", err
		} else {
			myConnPool := SingleConnPool{t: &tp, cConn: cConn}
			tp.ConnPool = myConnPool

			resp, err = tp.RoundTrip(req)
			if err != nil {
				return 0, nil, "", nil
			}

			err = cConn.Shutdown(ctx)
		}
	} else {
		if err := req.Write(conn); err != nil {
			return -1, nil, "", err
		}
		resp, err = http.ReadResponse(bufio.NewReader(conn), req)
	}
	if err != nil {
		return -1, nil, "", err
	}
	//// Close response in order to make additional requests
	err = resp.Body.Close()

	return resp.StatusCode, resp.Header, resp.Proto, err
}
