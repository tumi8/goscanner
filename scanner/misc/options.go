package misc


type Options struct {
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

	Scans []string `short:"r" long:"scans" description:"A list of scans to run. Choose of tls,http,scvs,ssh. Some can be combined like tls,http for https scans. Order is important"`
}
