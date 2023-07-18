package misc

import "github.com/tumi8/goscanner/scanner/cmd"

type Options struct {
	Config string `short:"C" long:"config" description:"Config file with options" no-ini:"true" value-name:"CONFIG-FILE"`

	Input     string `short:"i" long:"input-file" description:"Input file/named pipe with IPs or input directory. Reads from Stdin if '-'" value-name:"INPUT"`
	OutputDir string `short:"o" long:"output" description:"Output directory for scan results. If it already exists, the program will exit" value-name:"OUTPUT-DIR"`
	LogFile   string `short:"l" long:"log-file" description:"Log to file LOG-FILE (JSON formatted) instead of stderr" value-name:"LOG-FILE"`
	HashCache string `long:"hash-cache" description:"Change hash cache algorithm to save RAM. With 'none' the complete certificate will be kept in memory, propably using up all your RAM" choice:"sha1" choice:"sha256" choice:"none" default:"sha1"`

	Concurrency int   `short:"c" long:"concurrency" description:"Number of concurrent scanning goroutines." default:"0" default-mask:"qps * (max(timeout,syn-timeout) in seconds"`
	QPS         int   `short:"q" long:"qps" description:"Number of queries per second" default:"100"`
	Timeout     int64 `short:"t" long:"timeout" description:"Timeout for each connection in milliseconds" default:"10000"`
	SynTimeout  int64 `long:"syn-timeout" description:"Timeout for the TCP connection setup in milliseconds." default:"0" default-mask:"timeout"`

	SourceIP string `long:"source" description:"Source IP address if host has multiple addresses or interfaces" value-name:"SOURCE-IP" default:""`

	Profile string `short:"p" long:"profile" description:"Output file for profiling"`

	SkipErrors bool   `long:"skip-errors" description:"Skip TCP errors like connection timeout and don't write them to output file"`
	Verbose    []bool `short:"v" long:"verbose" description:"Increase verbosity from warning to info or even debug"`
	Version    bool   `short:"V" long:"version" description:"Show version information"`

	HTTPHeaders  string   `long:"http-headers" description:"Establish HTTP connection and store headers specified as comma-separated list. No HTTP connection if omitted"`
	HTTPRequests []string `long:"http-request" description:"Establish HTTP connection and perform request to URL. Format: REQUEST-METHOD,PATH, e.g. GET,index.html. Can be specified more than once. Default: HEAD,/"`
	SCSV         bool     `long:"scsv" description:"Send SCSV pseudo cipher suite"`

	CustomClientHello    string `long:"client-hello" description:"tls ClientHello Preset as binary gob file" value-name:"CustomClientHello"`
	CustomClientHelloDir string `long:"client-hello-dir" description:"tls ClientHello Preset directory with binary gob files. Used if a specific Client Hello is defined in the input file" value-name:"CustomClientHelloDir"`

	SSH bool `long:"ssh" description:"Scan SSH instead of TLS"`

	Scans      []string `short:"r" long:"scans" description:"A list of scans to run. Choose of tls,http,scvs,ssh. Some can be combined like tls,http for https scans. Order is important"`
	MemProfile bool     `long:"mem-profile" description:"Dump Mem Profile Files every 5 min to output directory"`

	TLSExtendedExport           bool `long:"tls-extended-output" description:"Save a more verbose output of the tls scan, including tls extensions and fingerprint"`
	HTTPExtendedExport          bool `long:"http-extended-output" description:"Save a verbose output for the http scan. This includes all HTTP headers."`
	TLSSaveStapledOcspResponses bool `long:"tls-save-stapled-ocsp" description:"Save stapled ocsp-responses in a separate file"`
	StartTLS                    bool `long:"starttls" description:"A list of protocols to attempt with StartTLS."`

	KeyLogFile bool `long:"keylog-file" description:"If set a keylog file will be written to the output"`

	CreateCHCommand             cmd.CreateCHCommand             `command:"create-ch" description:"Create Client Hellos"`
	CreateCHInputCommand        cmd.CreateCHInputCommand        `command:"create-ch-input" description:"Generate Cross Product between Client Hellos and input file"`
	GenerateFingerprintsCommand cmd.GenerateFingerprintsCommand `command:"generate-fingerprints" description:"Generate the Active TLS Stack Fingerprints from a Goscanner output"`

	DissecTLSMode        string  `long:"dissectls-mode" description:"Set the mode of the DeppTLSScan: 'recommended', 'go', 'all'" default:"all"`
	DissecTLSMaxCHs      int     `long:"dissectls-max-chs" description:"Max Number of CHS for the DeppTLSScan" default:"100"`
	DissecTLSQps         float64 `long:"dissectls-qps" description:"QPS to to scan the same target" default:"10"`
	DissecTLSLightweight bool    `long:"dissectls-light" description:"Use fewer requests, might not find as much details about the servers"`
}
