package main

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner"
	"github.com/tumi8/goscanner/scanner/cmd"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	log2 "log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"syscall"
	"time"
)

var GitBranch, GitHash string

// opts specifies the command line arguments
var opts misc.Options

func init() {
	// Set the number of Go processes to the number of CPUs
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	log.Logger = log.Output(zerolog.NewConsoleWriter())

	// Option parser
	parser := flags.NewParser(&opts, flags.Default)

	var subCommand cmd.ScannerCommand
	parser.CommandHandler = func(command flags.Commander, args []string) error {
		if command, ok := command.(cmd.ScannerCommand); ok {
			subCommand = command
		} else if command != nil {
			log.Fatal().Msg("Command was not a ScannerCommand")
		}
		return nil
	}
	parser.SubcommandsOptional = true

	_, err := parser.Parse()

	// Parse command line arguments
	if err != nil {
		if err.(*flags.Error).Type == flags.ErrHelp {
			return
		} else if err.(*flags.Error).Type != flags.ErrRequired {
			log.Fatal().Err(err).Msg("Error parsing command line")
		}
	}

	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt) // syscall.SIGHUP and syscall.SIGTERM maybe as well

	cSigpipe := make(chan os.Signal, 1)
	signal.Notify(cSigpipe, syscall.SIGPIPE)
	go sigPipeListener(cSigpipe)

	// Parse config file
	if opts.Config != "" {
		iniParser := flags.NewIniParser(parser)
		iniParser.ParseAsDefaults = true

		err := iniParser.ParseFile(opts.Config)
		if err != nil {
			log.Fatal().Err(err).Str("file", opts.Config).Msg("Error parsing config file")
		}
	}
	if opts.Version {
		fmt.Printf("Git version hash %v\n", GitHash)
		os.Exit(1)
	}

	if opts.LogFile != "" {
		fh, err := os.Create(opts.LogFile)
		if err != nil {
			log.Fatal().Err(err).Str("file", opts.LogFile).Msg("Error creating log file")
		}
		log.Logger = log.Output(fh)
	}

	log2.SetOutput(misc.LogWriter{})

	if len(opts.Verbose) >= 2 {
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	} else if len(opts.Verbose) == 1 {
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	} else {
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	}

	log.Info().Str("branch", GitBranch).Str("hash", GitHash).Msg("")

	// By default the SynTimeout is the same as Timeout
	if opts.SynTimeout == 0 {
		opts.SynTimeout = opts.Timeout
	}

	// By default Concurrency is  qps * (max(timeout,syn-timeout) in seconds)
	if opts.Concurrency == 0 {
		opts.Concurrency = int(float64(opts.QPS) * (float64(misc.MaxInt64(opts.Timeout, opts.SynTimeout)) * float64(time.Millisecond) / float64(time.Second)))
	}

	if subCommand != nil {
		err := subCommand.Run()
		if err == cmd.ErrPrintHelp {
			parser.WriteHelp(os.Stderr)
		} else if err != nil {
			log.Fatal().Err(err).Msg("Error running command")
		}
		os.Exit(0)
	}

	// Check if all necessary options are given
	contextLoggerOpts := log.Fatal().Interface("options", opts)

	if opts.Input == "" {
		contextLoggerOpts.Msg("Input has to be given")
	} else if opts.Input == "-" && !misc.IsStdInPresent() {
		contextLoggerOpts.Msg("Stdin was defined as input but is not present.")
	}

	if err := os.Mkdir(opts.OutputDir, 0755); err != nil {
		log.Fatal().Str("directory", opts.OutputDir).Err(err).Msg("Output directory already exists")
	}

	// Check if CPU profiling should be done
	if opts.Profile != "" {
		cpuFile := filepath.Join(opts.OutputDir, opts.Profile)
		fh, err := os.Create(cpuFile)
		if err != nil {
			log.Fatal().Str("file", opts.Profile).Msg("Could not create profile file")
		}
		err = pprof.StartCPUProfile(fh)
		if err != nil {
			log.Err(err).Msg("Could not start CPU Profiling")
		}
		defer pprof.StopCPUProfile()
	}

	var addr *net.TCPAddr
	if opts.SourceIP != "" {
		addr = getAddr(opts.SourceIP)
	}

	misc.LoadClientHellos(&opts)

	if len(opts.Scans) == 0 {
		// Set the default behaviour
		if opts.SSH {
			opts.Scans = []string{"ssh"}
		} else {
			// If nothing is configured do TLS scan
			opts.Scans = []string{"tls"}
			// If HTTP Headers are given do http
			if opts.HTTPHeaders != "" || len(opts.HTTPRequests) != 0 {
				opts.Scans = append(opts.Scans, "http")
			}
			if opts.SCSV {
				opts.Scans = append(opts.Scans, "scvs")
			}
		}
	}

	var interruptTarget *scanner.Scanner
	go func() {
		<-c
		log.Log().Msg("INTERRUPTED - Gracefully shutting down. Press again to force exit")
		misc.PrintStacktrace(true)
		if interruptTarget != nil {
			interruptTarget.Interrupt()
		} else {
			log.Warn().Msg("Could not interrupt scanner")
		}
		if opts.Profile != "" {
			pprof.StopCPUProfile()
		}
		<-c
		log.Log().Msg("INTERRUPTED - Forcing exit")
		os.Exit(1)
	}()

	// Create scanner and start scanning
	var s *scanner.Scanner
	if opts.SSH {
		s = startScanner(addr, []string{"ssh"})
	} else {
		s = startScanner(addr, opts.Scans)
	}
	interruptTarget = s

	// Generate input targets
	go func() {
		scanner.ReadTargetsToChannel(opts, s.Input)
	}()

	// Process results
	var proc scanner.ResultProcessor
	if opts.SSH {
		fileHostKeys := filepath.Join(opts.OutputDir, results.FileHostKeys)
		fileHosts := filepath.Join(opts.OutputDir, results.FileHosts)
		fileRelations := filepath.Join(opts.OutputDir, results.FileRelations)
		proc = *scanner.NewSSHHostKeyHostProcessor(fileHostKeys, fileHosts, fileRelations, opts.SkipErrors)
	} else {

		cacheFunc := misc.GetSHA256
		if opts.HashCache == "sha1" {
			cacheFunc = misc.GetSHA1
		} else if opts.HashCache == "none" {
			cacheFunc = nil
		}

		proc = scanner.NewCsvProcessor(opts.OutputDir, opts.SkipErrors, cacheFunc)
	}

	// Process results
	scanner.Processor{ResultProcessor: proc, OutputChan: s.Output}.Process()

	if opts.MemProfile {
		misc.DumpMemProfile(opts.OutputDir, "final")
	}
}

func startScanner(addr *net.TCPAddr, activatesScans []string) *scanner.Scanner {
	// Create scanner and start scanning
	s := scanner.NewScanner(&opts, addr, activatesScans)
	s.Scan()
	return &s
}

// getAddr returns the correct *net.TCPAddr interface for an IP address in string format
func getAddr(sourceIP string) *net.TCPAddr {
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal().Err(err).Msg("")
	}

	for _, iface := range ifaces {
		// Only use IP address if specified as CIDR
		if strings.Split(iface.String(), "/")[0] == sourceIP {
			return &net.TCPAddr{IP: iface.(*net.IPNet).IP}
		}
	}

	log.Fatal().Str("ip", sourceIP).Interface("interface", ifaces).Msg("Source IP could not be matched to assigned interface addresses")
	return nil
}

func sigPipeListener(c chan os.Signal) {
	msg := <-c
	event := log.Debug()
	var rlim syscall.Rlimit
	err := syscall.Getrlimit(syscall.RLIMIT_NOFILE, &rlim)
	if err != nil {
		event.AnErr("RLimit fetching error", err)
	} else {
		event.Uint64("rlim.Max", rlim.Max)
		event.Uint64("rlim.Cur", rlim.Cur)
	}
	if runtime.GOOS == "linux" {
		misc.RunCommandToLog(exec.Command("bash", "-c", fmt.Sprintf("ls /proc/%v/fd | wc -l", os.Getpid())), event)
	}

	event.
		Str("Signal", msg.String()).
		Msg("SIGPIPE signal received, is there a problem with too many sockets?")
}
