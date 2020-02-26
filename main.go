package main

import (
	"fmt"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
	"time"

	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"github.com/tumi8/goscanner/scanner"
)

// opts specifies the command line arguments
var opts struct {
	Config string `short:"C" long:"config" description:"Config file with options" no-ini:"true" value-name:"CONFIG-FILE"`

	Input         string `short:"i" long:"input-file" description:"Input file/named pipe with IPs or input directory" value-name:"INPUT"`
	OutputDir     string `short:"o" long:"output" description:"Output directory for scan results. If it already exists, the program will exit" value-name:"OUTPUT-DIR"`
	DumpDir       string `short:"s" long:"dump" description:"Output directory for certificate dump" value-name:"DUMP-DIR"`
	DatabaseTable string `short:"d" long:"db-table" description:"Table name for PostgreSQL database" default:"simplehashes"`
	LogFile       string `short:"l" long:"log-file" description:"Log to file LOG-FILE (JSON formatted) instead of stderr" value-name:"LOG-FILE"`
	HashCache     string `long:"hash-cache" description:"Change hash chache algorithm to save RAM. With 'none' output certs will not be deduplicated" choice:"sha1" choice:"sha256" choice:"none" default:"sha256"`

	Concurrency int   `short:"c" long:"concurrency" description:"Number of concurrent scanning goroutines. By default it is (qps/1000)*(timeout + syn-timeout)" default:"0"`
	QPS         int   `short:"q" long:"qps" description:"Number of queries per second" default:"100"`
	Timeout     int64 `short:"t" long:"timeout" description:"Timeout for connections in milliseconds" default:"10000"`
	SynTimeout  int64 `long:"syn-timeout" description:"Timeout for the TCP connection setup in milliseconds. If not specified the same as Timeout" default:"0"`

	Seed      string `short:"S" long:"seed" description:"Seed for IP Generator" value-name:"SEED" default:""`
	Increment int64  `long:"increment" description:"How many IPs should be given out" value-name:"INCREMENT" default:"1"`
	Offset    int64  `long:"offset" description:"How many IPs should be skipped before start" value-name:"OFFSET" default:"0"`

	SourceIP string `long:"source" description:"Source IP address if host has multiple addresses or interfaces" value-name:"SOURCE-IP" default:""`

	Profile string `short:"p" long:"profile" description:"Output file for profiling"`

	SkipErrors bool   `long:"skip-errors" description:"Skip TCP errors like connection timeout and don't write them to output file"`
	Verbose    []bool `short:"v" long:"verbose" description:"Increase verbosity from warning to info or even debug"`
	Version    bool   `short:"V" long:"version" description:"Show version information"`

	HTTPHeaders  string   `long:"http-headers" description:"Establish HTTP connection and store headers specified as comma-separated list. No HTTP connection if omitted"`
	HTTPRequests []string `long:"http-request" description:"Establish HTTP connection and perform request to URL. Format: REQUEST-METHOD,PATH, e.g. GET,index.html. Can be specified more than once"`
	SCSV         bool     `long:"scsv" description:"Send SCSV pseudo cipher suite"`

	SSH bool `long:"ssh" description:"Scan SSH instead of TLS"`
}

// Output files
const (
	fileHosts = "hosts.csv"

	// files to save SSH scan results
	fileHostKeys  = "host_keys.csv"
	fileRelations = "relations.csv"

	// files to save TLS scan results
	fileCerts       = "certs.csv"
	fileCertHostRel = "cert_rel.csv"
	fileScsv        = "scsv.csv"
	fileHttp        = "http.csv"
)

func init() {
	// Set the number of Go processes to the number of CPUs
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	// Option parser
	parser := flags.NewParser(&opts, flags.Default)

	// Parse command line arguments
	if _, err := parser.Parse(); err != nil {
		if err.(*flags.Error).Type == flags.ErrHelp {
			return
		} else if err.(*flags.Error).Type != flags.ErrRequired {
			log.Fatal(err)
		}
	}

	// Parse config file
	if opts.Config != "" {
		iniParser := flags.NewIniParser(parser)
		iniParser.ParseAsDefaults = true

		err := iniParser.ParseFile(opts.Config)
		if err != nil {
			log.WithFields(log.Fields{
				"file": opts.Config,
			}).Fatal(err)
		}
	}

	if opts.Version {
		fmt.Println("Git version hash", scanner.ReadGitVersionFromAsset())
		os.Exit(0)
	}

	if opts.LogFile != "" {
		fh, err := os.Create(opts.LogFile)
		if err != nil {
			log.WithFields(log.Fields{
				"file": opts.LogFile,
			}).Fatal("Could not create log file")
		}
		log.SetOutput(fh)

		log.SetFormatter(&log.JSONFormatter{})
	}

	if len(opts.Verbose) >= 2 {
		log.SetLevel(log.DebugLevel)
	} else if len(opts.Verbose) == 1 {
		log.SetLevel(log.InfoLevel)
	} else {
		log.SetLevel(log.WarnLevel)
	}

	// Check if CPU profiling should be done
	if opts.Profile != "" {
		fh, err := os.Create(opts.Profile)
		if err != nil {
			log.WithFields(log.Fields{
				"file": opts.Profile,
			}).Fatal("Could not create profile file")
		}
		pprof.StartCPUProfile(fh)
		defer pprof.StopCPUProfile()
	}

	// By default the SynTimeout is the same as Timeout
	if opts.SynTimeout == 0 {
		opts.SynTimeout = opts.Timeout
	}

	// By default Concurrency is (qps/1000)*(timeout + syn-timeout)
	if opts.Concurrency == 0 {
		opts.Concurrency = int(math.Max(1, (float64(opts.QPS)/1000.0)*float64(opts.Timeout+opts.SynTimeout)))
	}

	// Check if all necessary options are given
	contextLoggerOpts := log.WithFields(log.Fields{
		"options": opts,
	})

	if (opts.Input == "" && opts.Seed == "") || (opts.Input != "" && opts.Seed != "") {
		contextLoggerOpts.Fatal("Either input or seed must be specified")
	}

	if err := os.Mkdir(opts.OutputDir, 0755); err != nil {
		contextLoggerOpts.Fatal("Output directory already exists")
	}

	var addr *net.TCPAddr
	if opts.SourceIP != "" {
		addr = getAddr(opts.SourceIP)
	}

	// Live scanning and database writing
	if opts.DumpDir != "" {

		// Get input files, output files and certificate dump directory
		inFiles, outFiles, dumpDirs := getFiles(opts.Input, opts.OutputDir, opts.DumpDir)

		// Do scanning for all valid input files
		for i, inFile := range inFiles {
			outFile := outFiles[i]
			dumpDir := dumpDirs[i]

			// Create scanner and start scanning
			s := startTLSScanner(addr)

			go func() {
				scanner.ReadTargetsFromJSON(inFile, s.InputChannel(), scanner.NewMultiTLSTarget)
			}()

			proc, err := scanner.NewTLSLiveProcessor(outFile, dumpDir, opts.DatabaseTable)

			if err != nil {
				log.WithFields(log.Fields{
					"outFile":       outFile,
					"dumpDir":       dumpDir,
					"databaseTable": opts.DatabaseTable,
				}).Fatal(err)
			}

			scanner.Processor{ResultProcessor: proc, OutputChan: s.OutputChannel()}.Process()
		}
	} else {
		// Create scanner and start scanning
		var s scanner.Scanner
		var target func(string) scanner.Target
		if opts.SSH {
			s = startSSHScanner(addr)
			target = scanner.NewSSHTarget
		} else {
			s = startTLSScanner(addr)
			target = scanner.NewCertHostTLSTarget
		}

		// Generate input targets
		go func() {
			if opts.Input != "" {
				scanner.ReadIPsFromTxt(opts.Input, s.InputChannel(), target)
			} else {
				scanner.GenerateTargetsFromSeed(opts.Seed, opts.Increment, opts.Offset, s.InputChannel(), target)
			}
		}()

		// Process results
		var proc scanner.ResultProcessor
		if opts.SSH {
			fileHostKeys := filepath.Join(opts.OutputDir, fileHostKeys)
			fileHosts := filepath.Join(opts.OutputDir, fileHosts)
			fileRelations := filepath.Join(opts.OutputDir, fileRelations)

			proc = scanner.NewSSHHostKeyHostProcessor(fileHostKeys, fileHosts, fileRelations, opts.SkipErrors)
		} else {
			fileCerts := filepath.Join(opts.OutputDir, fileCerts)
			fileHosts := filepath.Join(opts.OutputDir, fileHosts)
			fileCertHostRel := filepath.Join(opts.OutputDir, fileCertHostRel)
			fileScsv := filepath.Join(opts.OutputDir, fileScsv)
			fileHttp := filepath.Join(opts.OutputDir, fileHttp)

			if !opts.SCSV {
				fileScsv = ""
			}

			if opts.HTTPHeaders == "" && len(opts.HTTPRequests) == 0 {
				fileHttp = ""
			}

			hashCache := scanner.HashCacheSHA256
			if opts.HashCache == "sha1" {
				hashCache = scanner.HashCacheSHA1
			} else if opts.HashCache == "none" {
				hashCache = scanner.HashCacheNone
			}

			proc = scanner.NewTLSCertHostProcessor(fileCerts, fileHosts, fileCertHostRel, fileScsv, fileHttp, opts.SkipErrors, hashCache)
		}

		// Process results
		scanner.Processor{ResultProcessor: proc, OutputChan: s.OutputChannel()}.Process()
	}
}

// startSSHScanner creates a SSHScanner, starts the scanning routine and returns the scanner
func startSSHScanner(addr *net.TCPAddr) scanner.Scanner {
	// Create scanner and start scanning
	s := scanner.Scanner{ProtocolScanner: scanner.NewSSHScanner(), NumRoutines: opts.Concurrency, QPS: opts.QPS, ConnTimeout: time.Duration(opts.Timeout) * time.Millisecond, SynTimeout: time.Duration(opts.SynTimeout) * time.Millisecond, SourceIP: addr, InputFile: opts.Input}
	s.Scan()
	return s
}

// startTLSScanner creates a TLSScanner, starts the scanning routine and returns the scanner
func startTLSScanner(addr *net.TCPAddr) scanner.Scanner {
	// Create scanner and start scanning
	s := scanner.Scanner{ProtocolScanner: scanner.NewTLSScanner(opts.HTTPHeaders, opts.HTTPRequests, opts.SCSV), NumRoutines: opts.Concurrency, QPS: opts.QPS, ConnTimeout: time.Duration(opts.Timeout) * time.Millisecond, SynTimeout: time.Duration(opts.SynTimeout) * time.Millisecond, SourceIP: addr, InputFile: opts.Input}
	s.Scan()
	return s
}

// getAddr returns the correct *net.TCPAddr interface for an IP address in string format
func getAddr(sourceIP string) *net.TCPAddr {
	ifaces, err := net.InterfaceAddrs()
	if err != nil {
		log.Fatal(err)
	}

	for _, iface := range ifaces {
		// Only use IP address if specified as CIDR
		if strings.Split(iface.String(), "/")[0] == sourceIP {
			return &net.TCPAddr{IP: iface.(*net.IPNet).IP}
		}
	}

	log.WithFields(log.Fields{
		"ip":         sourceIP,
		"interfaces": ifaces,
	}).Fatal("Source IP could not be matched to assigned interface addresses")
	return nil
}

// getFiles returns slices of valid input files, output files and dump directories
func getFiles(inputDir, outputDir, scannedDir string) ([]string, []string, []string) {
	var inRet, outRet, dumpRet []string

	// Get input files from input directory
	fh, err := os.OpenFile(inputDir, os.O_RDONLY, os.ModeDir)
	if err != nil {
		log.WithFields(log.Fields{
			"directory": inputDir,
		}).Fatal(err)
	}

	inFiles, err := fh.Readdirnames(0)
	if err == io.EOF {
		log.WithFields(log.Fields{
			"directory": inputDir,
		}).Fatal("No input file found")
	} else if err != nil {
		log.WithFields(log.Fields{
			"directory": inputDir,
		}).Fatal(err)
	}

	// Iterate through all potential input files
	for _, inFile := range inFiles {

		inFile = filepath.Join(inputDir, inFile)

		// Extract timestamp from input file name
		_, file := filepath.Split(inFile)
		timestamp := file[:strings.Index(file, "_")]

		// Get output file
		outFile := filepath.Join(outputDir, timestamp+"_submoas.results")

		// Get cert dump directory
		dumpDir := filepath.Join(scannedDir, timestamp, "certs")

		// Only scan the files if the dump directory does NOT yet exist
		if _, err := os.Stat(dumpDir); os.IsNotExist(err) {
			inRet = append(inRet, inFile)
			outRet = append(outRet, outFile)
			dumpRet = append(dumpRet, dumpDir)
		}
	}

	return inRet, outRet, dumpRet
}

// Download and update the tls-parameters-4.csv asset file
//go:generate wget -q -O tls-parameters-4.csv http://www.iana.org/assignments/tls-parameters/tls-parameters-4.csv
//go:generate go get -u github.com/tmthrgd/go-bindata/...
//go:generate go-bindata -pkg asset -o scanner/asset/assets.go tls-parameters-4.csv git-version
//go:generate rm tls-parameters-4.csv
