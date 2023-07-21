package scans

/*
This LDAP scanner is not yet ready, so it should not be added in the scanning pipeline
*/

import (
	"github.com/go-ldap/ldap/v3"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"golang.org/x/time/rate"
	"io"
	"net"
	"strconv"
	"time"
)

type LDAPScan struct {
	keyLogFile io.Writer
}

func (s *LDAPScan) Init(opts *misc.Options, keylogFile io.Writer) {
	s.keyLogFile = keylogFile
}

func (s *LDAPScan) GetDefaultPort() int {
	return 389
}

func (s *LDAPScan) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (net.Conn, error) {
	var ldapHostName string

	// not mandatory to have domain names, IP only should be sufficient
	if target.Domain != "" {
		ldapHostName = target.Domain
	} else {
		ldapHostName = target.Ip
	}
	port, err := target.Port()
	if err != nil {
		port = strconv.Itoa(s.GetDefaultPort())
	}

	// connection without TLS
	l, err := ldap.Dial("tcp", net.JoinHostPort(ldapHostName, port))
	if err != nil {
		log.Debug().Str("err", err.Error()).Msg("Error connecting to ldap server")
		addResult(result, synStart, synEnd, err, &results.LDAPResult{LdapError: err})
		return nil, err
	}

	// TODO do we need to bind to retrieve the ldap version?
	err = l.UnauthenticatedBind("login")

	if err != nil {
		log.Debug().Str("err", err.Error()).Msg("Error binding to ldap server")
	}

	addResult(result, synStart, synEnd, err, &results.LDAPResult{})

	return conn, nil
}
