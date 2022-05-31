package results

import (
	"crypto/x509"
	"encoding/csv"
	"github.com/tumi8/goscanner/scanner/misc"
	"strconv"
	"time"
)

var chrCsvHeader = []string{"id", "cert_chain", "chain_complete", "x509_uncompliant_signature_chain_index"}

type chainRoot int

const (
	NoRoot      chainRoot = 0
	SystemStore chainRoot = 1
	Loop        chainRoot = 2
)

func (cR chainRoot) String() string {
	switch cR {
	case NoRoot:
		return "NoRoot"
	case SystemStore:
		return "SystemStore"
	case Loop:
		return "Loop"
	default:
		return ""
	}
}

type CertRelationResult struct {
	Chain []x509.Certificate
	Root  chainRoot
}

func (t *CertRelationResult) GetCsvFileName() string {
	return FileCertHostRel
}

func (t *CertRelationResult) GetCsvHeader() []string {
	return chrCsvHeader
}

func (t *CertRelationResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {
	// Write to certificate relation CSV file

	var x509Uncompliant []string

	// Parse Certificates to hash key
	chain := make([]int, len(t.Chain))

	for j := range t.Chain {
		id, _ := certCache.GetID(&t.Chain[j])
		chain[j] = int(id)
	}

	x509Uncompliant = getX509uncompliantIndeces(t.Chain)

	err := writer.Write([]string{parentResult.Id.ToString(), misc.ToJSONIntArray(chain), strconv.Itoa(int(t.Root)), misc.ToJSONArray(x509Uncompliant)})
	return err
}

func getX509uncompliantIndeces(chain []x509.Certificate) []string {
	var lastCert *x509.Certificate
	var result []string
	for i, cert := range chain {
		if lastCert != nil {
			// Copy from x509.CheckSignatureFrom
			if cert.Version == 3 && !cert.BasicConstraintsValid ||
				cert.BasicConstraintsValid && !cert.IsCA {
				result = append(result, strconv.Itoa(i-1))
				continue
			}

			if cert.KeyUsage != 0 && cert.KeyUsage&x509.KeyUsageCertSign == 0 {
				result = append(result, strconv.Itoa(i-1))
				continue
			}
		}
		lastCert = &cert
	}
	return result
}

func TrimLoop(certs []*x509.Certificate) ([]*x509.Certificate, bool) {
	for i := 1; i < len(certs); i++ {
		if certs[i-1] == certs[i] {
			return certs[:i], true
		}

	}
	return certs, false
}
