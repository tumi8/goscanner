package scans

import (
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"net"
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

func (st Target) Port() (string, error) {
	_, port, err := net.SplitHostPort(st.Ip)
	if err != nil {
		log.Debug().Str("address", st.Ip).Msg(err.Error())
	}
	return port, err
}
