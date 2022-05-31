// Copyright 2011 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package misc

import (
	"bytes"
	"crypto/x509"
	"github.com/rs/zerolog/log"
	"reflect"
	"unsafe"
)

var systemCertStore *x509.CertPool

func getSystemStore() *x509.CertPool {
	if systemCertStore == nil {
		var err error
		systemCertStore, err = x509.SystemCertPool()
		if err != nil {
			log.Panic().Err(err).Msg("Could not load system Cert Pool")
		}
	}
	return systemCertStore
}

var getCertTypeReflect = reflect.TypeOf(func() (*x509.Certificate, error) { return nil, nil })

func getFromSystemStore(i int) *x509.Certificate {
	pool := getSystemStore()

	certificates := reflect.ValueOf(pool).Elem().FieldByName("lazyCerts")
	if certificates.IsValid() && !certificates.IsZero() { // version > go1.15.0
		lazyCert := certificates.Index(i)
		if lazyCert.IsValid() && !lazyCert.IsZero() {

			getLazyCert := lazyCert.FieldByName("getCert")

			getCertPtr := reflect.NewAt(getCertTypeReflect, unsafe.Pointer(getLazyCert.UnsafeAddr())).Elem()

			result := getCertPtr.Call([]reflect.Value{})

			if !result[1].IsNil() {
				log.Err(result[1].Interface().(error)).Msg("Error while getting cert with reflect")
				return nil
			}
			return result[0].Interface().(*x509.Certificate)
		}
		return nil
	}

	certificates = reflect.ValueOf(pool).Elem().FieldByName("certs")
	cert := certificates.Index(i)
	if cert.IsValid() && !cert.IsZero() {
		cert = reflect.NewAt(cert.Type(), unsafe.Pointer(cert.UnsafeAddr())).Elem()
		return cert.Interface().(*x509.Certificate)
	}
	return nil
}

func findPotentialParentsSystemStore(cert *x509.Certificate) []int {
	pool := getSystemStore()

	var candidates []int

	if len(cert.RawIssuer) > 0 {
		byName := reflect.ValueOf(pool).Elem().FieldByName("byName")
		c := byName.MapIndex(reflect.ValueOf(string(cert.RawIssuer)))
		if c.IsValid() && !c.IsZero() {
			l := c.Len()
			candidates = make([]int, l)
			for i := 0; i < l; i++ {
				candidates[i] = int(c.Index(i).Int())
			}
		}
	}
	return candidates
}

// CertPool is a set of certificates.
type CertPool struct {
	certs          []*x509.Certificate
	useSystemStore bool
}

// NewCertPool returns a new, empty CertPool.
func NewCertPool(certs []*x509.Certificate, withSystemStore bool) *CertPool {
	pool := &CertPool{certs: nil, useSystemStore: withSystemStore}
	for _, cert := range certs {
		contained := false
		for _, p := range pool.certs {
			if p.Equal(cert) {
				contained = true
				break
			}
		}
		if !contained {
			pool.certs = append(pool.certs, cert)
		}
	}
	return pool
}

// findPotentialParents returns the indexes of certificates in s which might
// have signed cert. The caller must not modify the returned slice.
func (s *CertPool) FindPotentialParents(cert *x509.Certificate) []int {
	if s == nil {
		return nil
	}
	var candidates []int

	if s.useSystemStore {
		c := findPotentialParentsSystemStore(cert)
		for _, i := range c {
			candidates = append(candidates, i+len(s.certs))
		}
	}

issuerLoop:
	for i := range s.certs {
		if bytes.Equal(cert.RawIssuer, s.certs[i].RawSubject) {
			for _, rootCerts := range candidates {
				if rootCerts >= len(s.certs) && getFromSystemStore(rootCerts-len(s.certs)).Equal(s.certs[i]) {
					continue issuerLoop
				}
			}
			candidates = append(candidates, i)
		}
	}

	return candidates
}

func (s *CertPool) IsFromSystemStore(i int) bool {
	if s == nil {
		return false
	}
	if i >= len(s.certs) {
		return true
	}
	return false
}

func (s *CertPool) N() int {
	return len(s.certs)
}

func (s *CertPool) Get(i int) *x509.Certificate {
	if i >= len(s.certs) {
		return getFromSystemStore(i - len(s.certs))
	}
	return s.certs[i]
}
