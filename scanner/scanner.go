package scanner

import (
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/scanner/scans"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var ALL_SCANS = map[string]Scans{
	"tls":  &scans.TLSScan{},
	"http": &scans.HTTPScan{},
	"ssh":  &scans.SSHScan{},
	"scvs": &scans.SCSVScan{},
}

type Scans interface {
	Init(opts *misc.Options, keylogFile io.Writer)
	GetDefaultPort() int
	Scan(conn net.Conn, target *scans.Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time) (net.Conn, error)
}

// Scanner is the base struct that handles the scanning loop
type Scanner struct {
	NumRoutines    int
	QPS            int
	ConnTimeout    time.Duration
	SynTimeout     time.Duration
	SourceIP       *net.TCPAddr
	InputFile      string
	scans          []Scans
	scanNames      []string
	Input          chan *scans.Target
	Output         chan *results.ScanResult
	interrupted    bool
	queries        uint64
	targets        uint64
	dumpMemProfile string
}

func NewScanner(opts *misc.Options, addr *net.TCPAddr, activatedScans []string) Scanner {

	loadedScans := make([]Scans, len(activatedScans))
	for i, s := range activatedScans {
		loadedScans[i] = ALL_SCANS[s]
		if loadedScans[i] == nil {
			var all []string
			for s2 := range ALL_SCANS {
				all = append(all, s2)
			}
			log.Fatal().Strs("available scans", all).Str("scan", s).Msg("Could not find scan")
		}
		var keylogFile io.Writer
		if opts.KeyLogFile {
			var keyLogPath = filepath.Join(opts.OutputDir, results.FileKeyLog)
			var err error
			keylogFile, err = os.Create(keyLogPath)
			if err != nil {
				log.Fatal().Err(err).Msg("Cannot create key log file!")
			}
		}
		loadedScans[i].Init(opts, keylogFile)
	}

	log.Info().Strs("scans", activatedScans).Msg("Conducting scans in order")
	var dumpMemProfile string
	if opts.MemProfile {
		dumpMemProfile = opts.OutputDir
	}

	return Scanner{
		NumRoutines:    opts.Concurrency,
		QPS:            opts.QPS,
		ConnTimeout:    time.Duration(opts.Timeout) * time.Millisecond,
		SynTimeout:     time.Duration(opts.SynTimeout) * time.Millisecond,
		SourceIP:       addr,
		InputFile:      opts.Input,
		scans:          loadedScans,
		scanNames:      activatedScans,
		Input:          make(chan *scans.Target, 10000),
		Output:         make(chan *results.ScanResult),
		interrupted:    false,
		dumpMemProfile: dumpMemProfile,
	}
}

const statsEverySeconds = 5 * 60

// Scan executes the scanning loop. It is non-blocking.
func (s *Scanner) Scan() {

	// Limit the queries per second
	limiter := rate.NewLimiter(rate.Limit(s.QPS), 1)
	ctx := context.Background()

	// wg makes sure that all scanning goroutines have terminated before exiting
	var wg sync.WaitGroup

	log.Info().
		Int("NumRoutines", s.NumRoutines).
		Int("QPS", s.QPS).
		Dur("ConnTimeout", s.ConnTimeout).
		Dur("SynTimeout", s.SynTimeout).
		Interface("SourceIP", s.SourceIP).
		Msg("Scanning started")

	for i := 0; i < s.NumRoutines; i++ {
		wg.Add(1)
		go s.scanThread(&wg, limiter, ctx)
	}

	go func() {
		// Close channel when scanning is finished
		defer close(s.Output)
		wg.Wait()
		log.Info().Msg("Scanning stopped")
	}()

	go func() {
		if s.InputFile != "" && s.InputFile != "-" {
			num, err := LineCounter(s.InputFile)
			if err != nil {
				log.Err(err).Str("file", s.InputFile).Msg("")
			}
			log.Info().Int64("total", num).Msg("Number of targets")
			s.targets = uint64(num)
		}
	}()

	// Print queries per seconds
	go s.PrintStatus()
}

func (s *Scanner) PrintStatus() {
	var numQueries uint64
	tickerChan := time.NewTicker(statsEverySeconds * time.Second)
	var currQueries uint64
	var m runtime.MemStats
	for {
		select {
		case <-tickerChan.C:
			numQueries = s.queries
			qps := (numQueries - currQueries) / statsEverySeconds
			var eta time.Duration
			if s.targets != 0 && qps != 0 {
				eta = time.Duration((s.targets-numQueries)/qps) * time.Second
			}
			log.Info().
				Uint64("qps", qps).
				Uint64("totalQueries", numQueries).
				Dur("eta in ms", eta).
				Msg("Status update")
			memStatsLog := log.Debug()
			if memStatsLog.Enabled() {
				runtime.ReadMemStats(&m)
				memStatsLog.
					Str("Heap Allocation", misc.ByteToMb(m.Alloc)).
					Str("Total Heap Allocation", misc.ByteToMb(m.TotalAlloc)).
					Str("Virtual Address Space", misc.ByteToMb(m.Sys)).
					Uint32("GC Cycles", m.NumGC).
					Msg("MemStats")
			}
			currQueries = numQueries
		}
	}
}

func (s *Scanner) Interrupt() {
	s.interrupted = true
}

func (s *Scanner) scanThread(wgScoped *sync.WaitGroup, limiterScoped *rate.Limiter, ctx context.Context) {

	for target, ok := <-s.Input; ok && !s.interrupted; target, ok = <-s.Input {

		err := limiterScoped.Wait(ctx)
		if err != nil {
			log.Debug().Err(err).Msg("Error while waiting for query limiter")
		}
		atomic.AddUint64(&s.queries, 1)

		s.Output <- s.scanTarget(target)
	}

	wgScoped.Done()
}

func (s *Scanner) scanTarget(target *scans.Target) *results.ScanResult {
	// Establish TCP connection with timeout
	synStart := time.Now().UTC()
	dialer := net.Dialer{Timeout: s.SynTimeout, LocalAddr: s.SourceIP}
	synEnd := time.Now().UTC()

	address := target.Address(s.scans[0].GetDefaultPort())

	result := results.ScanResult{
		SubResults: make([]results.ScanSubResult, 0),
		Id:         misc.GetSessionUID(),
		Ip:         target.Ip,
		Domain:     target.Domain,
		CHName:     target.CHName,
		Address:    address,
	}

	conn, err := dialer.Dial("tcp", address)
	defer func() {
		if conn != nil {
			err = conn.SetDeadline(time.Now().Add(s.ConnTimeout))
			if err != nil && misc.IsClosedConnErr(err) {
				return
			}
			if err != nil {
				log.Err(err).Str("ip", address).Str("dn", target.Domain).Msg("Could not set deadline for close")
			}
			err := conn.Close()
			if err != nil {
				log.Debug().Err(err).Str("ip", address).Str("dn", target.Domain).Msg("Error closing TCP socket")
			}
		}
	}()

	if err != nil {
		result.AddResult(results.ScanSubResult{
			SynStart: synStart,
			SynEnd:   synEnd,
			Result:   &results.TCPResult{Err: err},
		})
		log.Debug().Err(err).Str("ip", address).Str("dn", target.Domain).Msg("Error connecting to host")
		return &result
	}

	for j := range s.scans {
		if conn != nil {
			err = conn.SetDeadline(time.Now().Add(s.ConnTimeout))
			if err != nil {
				log.Err(err).Str("ip", address).Str("dn", target.Domain).Str("scan", s.scanNames[j]).Msg("Could not set new deadline for scan")
			}
		}
		conn, err = s.scans[j].Scan(conn, target, &result, s.ConnTimeout, synStart, synEnd)
		if err != nil {
			log.Debug().Err(err).Str("ip", address).Str("dn", target.Domain).Str("scan", s.scanNames[j]).Str("Client-Hello", target.CHName).Msg("Error during scan")
			return &result
		}
	}
	return &result
}
