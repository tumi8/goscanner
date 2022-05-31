package scans

import (
	"github.com/tumi8/goscanner/scanner/misc"
)

type Target struct {
	Ip     string
	Domain string
	CHName string
}

func (st Target) Address(defaultPort int) string {
	return misc.AddDefaultPort(st.Ip, defaultPort)
}

func (st Target) Targets() []Target {
	return []Target{st}
}

func (st Target) Input() string {
	return st.Ip + "," + st.Domain
}
