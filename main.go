package main

import (
	"fmt"
	"github.com/jessevdk/go-flags"
	log "github.com/sirupsen/logrus"
	"github.com/tumi8/goscanner/scanner"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"io"
	"math"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strings"
)

// opts specifies the command line arguments
var opts misc.Options

func init() {
	// Set the number of Go processes to the number of CPUs
	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {
	// Option parser
	parser := flags.NewParser(&opts, flags.Default)
	_, err := parser.Parse()

	// Parse command line arguments
	if err != nil {
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

	if len(opts.Scans) == 0 {
		opts.Scans = []string{"tls"}
		log.Info("Automatically activated TLS scan")
		if opts.HTTPHeaders != "" || len(opts.HTTPRequests) != 0 {
			opts.Scans = append(opts.Scans, "http")
			log.Info("Automatically activated HTTP scan")
		}

	}

	if opts.SCSV {
		opts.Scans = append(opts.Scans, "scvs")
		log.Info("Automatically activated SCSV scan")
	}

	if opts.SSH {
		opts.Scans = []string{"ssh"}
		log.Info("Automatically activated just SSH scan")
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
			s := startScanner(addr, opts.Scans)

			go func() {
				scanner.ReadSubmoaTargetsFromJSON(inFile, s.Input)
			}()

			proc, err := scanner.NewTLSLiveProcessor(outFile, dumpDir, opts.DatabaseTable)

			if err != nil {
				log.WithFields(log.Fields{
					"outFile":       outFile,
					"dumpDir":       dumpDir,
					"databaseTable": opts.DatabaseTable,
				}).Fatal(err)
			}

			scanner.Processor{ResultProcessor: *proc, OutputChan: s.Output}.Process()
		}
	} else {
		// Create scanner and start scanning
		var s scanner.Scanner
		if opts.SSH {
			s = startScanner(addr, []string{"ssh"})
		} else {
			s = startScanner(addr, opts.Scans)
		}

		// Generate input targets
		go func() {
			if opts.Input != "" {
				scanner.ReadIPsFromTxt(opts.Input, s.Input)
			} else {
				scanner.GenerateTargetsFromSeed(opts.Seed, opts.Increment, opts.Offset, s.Input)
			}
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
	}
}

func startScanner(addr *net.TCPAddr, activatesScans []string) scanner.Scanner {
	// Create scanner and start scanning
	s := scanner.NewScanner(&opts, addr, activatesScans)
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
