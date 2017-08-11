package scanner

// Target symbolizes a host or a group of hosts
type Target interface {
	IPs() []string
	Results() map[string]*ScanResult
	AddResult(string, *ScanResult)
	Domains() []string
}

// DumpableTarget allows to dump output in a directory
type DumpableTarget interface {
	Target
	Dump(dir string)
}

// JSONableTarget allows to create a JSON represenation of the target
type JSONableTarget interface {
	Target
	JSON() interface{}
}
