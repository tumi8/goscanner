package scanner

import (
	"net"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
)

// ProtocolScanner is used to implement protocol scanning
type ProtocolScanner interface {
	ScanProtocol(conn net.Conn, target *Target, timeout time.Duration, synStart time.Time, synEnd time.Time)
	InputChannel() chan *Target
	OutputChannel() chan *Target
}

// Scanner is the base struct that handles the scanning loop
type Scanner struct {
	ProtocolScanner
	NumRoutines int
	QPS         int
	ConnTimeout time.Duration
	SynTimeout  time.Duration
	SourceIP    *net.TCPAddr
	InputFile   string
}

const statsEverySeconds = 30

// Scan executes the scanning loop. It is non-blocking.
func (s Scanner) Scan() {

	// Limit the queries per second
	limiter := rate.NewLimiter(rate.Limit(s.QPS), 1)
	ctx := context.Background()
	effectiveQPS := make(chan interface{}, 1000)

	// wg makes sure that all scanning goroutines have terminated before exiting
	var wg sync.WaitGroup

	log.WithFields(log.Fields{
		"NumRoutines": s.NumRoutines,
		"QPS":         s.QPS,
		"ConnTimeout": s.ConnTimeout,
		"SynTimeout":  s.SynTimeout,
		"SourceIP":    s.SourceIP,
	}).Info("Scanning started")

	for i := 0; i < s.NumRoutines; i++ {
		go func(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, effectiveQPSScoped *chan interface{}) {
			wg.Add(1)

			for target, ok := <-s.InputChannel(); ok; target, ok = <-s.InputChannel() {

				// Some targets have multiple IPs
				for _, ip := range (*target).IPs() {

					limiter.Wait(ctx)
					*effectiveQPSScoped <- struct{}{}

					// Establish TCP connection with timeout
					synStart := time.Now().UTC()
					dialer := net.Dialer{Timeout: s.SynTimeout, LocalAddr: s.SourceIP}
					synEnd := time.Now().UTC()

					conn, err := dialer.Dial("tcp", ip)
					if err != nil {
						(*target).AddResult(ip, &ScanResult{synStart, synEnd, time.Time{}, err})
						continue
					}
					// Set connection deadline
					conn.SetDeadline(time.Now().Add(s.ConnTimeout))

					// Do the actual protocol scan, results will be set within this method
					s.ScanProtocol(conn, target, s.ConnTimeout, synStart, synEnd)

					// Close the connection
					conn.Close()
				}
				// Send target with results to channel
				s.OutputChannel() <- target
			}

			wg.Done()
		}(&wg, limiter, &effectiveQPS)
	}

	go func() {
		// Close channel when scanning is finished
		defer close(s.OutputChannel())
		wg.Wait()

		log.Info("Scanning stopped")
	}()

	// Number of targets
	var numTargets int64
	go func(numTargetsScoped *int64) {
		if s.InputFile != "" {
			num, err := LineCounter(s.InputFile)
			if err != nil {
				log.WithFields(log.Fields{
					"file": s.InputFile,
				}).Error(err)
			}
			*numTargetsScoped = num
		}
	}(&numTargets)

	// Print queries per seconds
	go func(effectiveQPSScoped *chan interface{}) {
		var numQueries int64
		tickerChan := time.NewTicker(statsEverySeconds * time.Second)
		go func(numQueriesScoped *int64, numTargets *int64) {
			var currQueries int64
			for {
				select {
				case <-tickerChan.C:
					qps := (numQueries - currQueries) / statsEverySeconds
					var eta time.Duration
					if *numTargets != 0 && qps != 0 {
						eta = time.Duration((*numTargets-numQueries)/qps) * time.Second
					}
					log.WithFields(log.Fields{
						"qps":          qps,
						"totalQueries": numQueries,
						"totalTargets": *numTargets,
						"eta":          eta,
					}).Info("ETA: ", eta, "\tQueries per second: ", qps)
					currQueries = numQueries
				}
			}
		}(&numQueries, &numTargets)

		for {
			<-*effectiveQPSScoped
			numQueries++
		}
	}(&effectiveQPS)
}
