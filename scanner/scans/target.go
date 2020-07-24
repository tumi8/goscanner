package scans

import (
	"github.com/tumi8/goscanner/scanner/misc"
)

type TargetBatch interface {
	Input()	  string
	Targets() []Target
}

type Target struct {
	Ip string
	Domain string
}

type SubmoaTarget struct {
	inputRaw   string
	Json    interface{}
	Targets_ []Target
}

func (st Target) Address (defaultPort int) string {
	return misc.AddDefaultPort(st.Ip, defaultPort)
}

func (st Target) Targets() []Target {
	return []Target{st}
}

func (st Target) Input() string {
	return st.Ip + "," + st.Domain
}

func (st SubmoaTarget) Targets() []Target {
	return st.Targets_
}

func (st SubmoaTarget) Input() string {
	return st.inputRaw
}