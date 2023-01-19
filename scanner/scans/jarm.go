package scans

import (
	jarmgo "github.com/hdm/jarm-go"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"io"
	"net"
	"strings"
	"time"
)

type JARMScan struct {
	Retries int
}

func (s *JARMScan) GetDefaultPort() int {
	return 443
}

func (s *JARMScan) Init(opts *misc.Options, keylogFile io.Writer) {
	s.Retries = 3
}

func (s *JARMScan) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (net.Conn, error) {

	addr := target.Address(s.GetDefaultPort())

	hostname := target.Domain

	if conn == nil {
		return nil, nil
	}

	localAddr, _, _ := net.SplitHostPort((conn).LocalAddr().String())

	ctx := context.Background()

	first := true

	collectedResults := []string{}
	var err2 error
	for _, probe := range jarmgo.GetProbes(hostname, s.GetDefaultPort()) {
		dialer := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(localAddr)}}

		c := net.Conn(nil)
		n := 0

		var err error

		for c == nil && n <= s.Retries {
			if !first {
				err = limiter.Wait(ctx)
			} else {
				first = false
			}
			if err != nil {
				return conn, err
			}

			if c, err = dialer.Dial("tcp", addr); c != nil || n >= s.Retries {
				break
			}

			time.Sleep(2 * time.Second)

			n++
		}

		if c == nil {
			return conn, err
		}

		data := jarmgo.BuildProbe(probe)

		c.SetWriteDeadline(time.Now().Add(time.Second * 5))

		_, err2 = c.Write(data)
		if err2 != nil {
			collectedResults = append(collectedResults, "")
			c.Close()
			continue
		}

		c.SetReadDeadline(time.Now().Add(time.Second * 5))
		buff := make([]byte, 1484)
		c.Read(buff)
		c.Close()

		var ans string
		ans, err2 = jarmgo.ParseServerHello(buff, probe)
		if err2 != nil {
			collectedResults = append(collectedResults, "")
			continue
		}

		collectedResults = append(collectedResults, ans)
	}

	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result: &results.JARMResult{
			Error:       err2,
			Fingerprint: jarmgo.RawHashToFuzzyHash(strings.Join(collectedResults, ",")),
			Raw:         strings.Join(collectedResults, ","),
		},
	})

	return conn, err2
}
