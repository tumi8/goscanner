package scanner

import (
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/scanner/scans"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
)

var ALL_SCANS = map[string]Scans {
	"tls":	&scans.TLSScan{},
	"http":	&scans.HTTPScan{},
	"ssh":	&scans.SSHScan{},
	"scvs": &scans.SCSVScan{},
}

type Scans interface {
	Init(opts *misc.Options)
	GetDefaultPort() int
	Scan(conn *net.Conn, target *scans.Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time) *net.Conn
}

// Scanner is the base struct that handles the scanning loop
type Scanner struct {
	NumRoutines int
	QPS         int
	ConnTimeout time.Duration
	SynTimeout  time.Duration
	SourceIP    *net.TCPAddr
	InputFile   string
	scans 		[]Scans
	Input 		chan *scans.TargetBatch
	Output 		chan *results.BatchScanResult
}

func NewScanner(opts *misc.Options, addr *net.TCPAddr, activatedScans []string) Scanner {

	loaded_scans := make([]Scans, len(activatedScans))
	for i,s := range activatedScans {
		loaded_scans[i] = ALL_SCANS[s]
		if loaded_scans[i] == nil {
			log.Fatal("Could not find scan: " + s)
		}
		loaded_scans[i].Init(opts)
	}

	log.Info("Conducting the following scans in order: " + strings.Join(activatedScans, ", "))

	return Scanner{
		NumRoutines: opts.Concurrency,
		QPS:         opts.QPS,
		ConnTimeout: time.Duration(opts.Timeout) * time.Millisecond,
		SynTimeout:  time.Duration(opts.SynTimeout) * time.Millisecond,
		SourceIP:    addr,
		InputFile:   opts.Input,
		scans:    	 loaded_scans,
		Input:		 make(chan *scans.TargetBatch, 10000),
		Output: 	 make(chan *results.BatchScanResult),
	}
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

			for batchTarget, ok := <-s.Input; ok; batchTarget, ok = <-s.Input {

				batchResult := results.BatchScanResult{Input: (*batchTarget).Input(), Results: make([]*results.ScanResult, len((*batchTarget).Targets()))}

				// Some targets have multiple IPs
				for i, target := range (*batchTarget).Targets() {

					limiter.Wait(ctx)
					*effectiveQPSScoped <- struct{}{}

					// Establish TCP connection with timeout
					synStart := time.Now().UTC()
					dialer := net.Dialer{Timeout: s.SynTimeout, LocalAddr: s.SourceIP}
					synEnd := time.Now().UTC()

					address := target.Address(s.scans[0].GetDefaultPort())

					conn, err := dialer.Dial("tcp", address)

					result := results.ScanResult{
						SubResults: make([]results.ScanSubResult, 0),
						Ip:     	target.Ip,
						Domain:		target.Domain,
						Address:	address,
					}
					batchResult.Results[i] = &result

					if err != nil {
						result.AddResult(results.ScanSubResult{synStart, synEnd, time.Time{}, &results.TLSResult{Err: err}})
						continue
					}

					// Set connection deadline
					conn.SetDeadline(time.Now().Add(s.ConnTimeout))

					for _, scan := range s.scans {
						conn = *scan.Scan(&conn, &target, &result, s.ConnTimeout, synStart, synEnd)
					}

					// Close the connection
					conn.Close()

					// Send target with results to channel
					batchResult.Results[i] = &result
				}
				s.Output <- &batchResult
			}

			wg.Done()
		}(&wg, limiter, &effectiveQPS)
	}

	go func() {
		// Close channel when scanning is finished
		defer close(s.Output)
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
