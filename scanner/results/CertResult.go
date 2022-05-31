package results

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"time"
)

// beginCertificate and endCertificate signal start and beginning of PEM-encoded TLS certificates
const beginCertificate = "-----BEGIN CERTIFICATE-----"
const endCertificate = "-----END CERTIFICATE-----"

var certCsvHeader = []string{"id", "cert", "system_cert_store"}

type CertResult struct {
	Depth       int
	Cert        *x509.Certificate
	SystemStore bool
}

func (t *CertResult) GetCsvFileName() string {
	return FileCerts
}

func (t *CertResult) GetCsvHeader() []string {
	return certCsvHeader
}

func (t *CertResult) WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool, certCache *misc.CertCache) error {

	id, isNew := certCache.GetID(t.Cert)

	// Check if certificate was already written out before
	if isNew {
		certString := misc.OpensslFormat(base64.StdEncoding.EncodeToString(t.Cert.Raw), beginCertificate, endCertificate)
		err := writer.Write([]string{id.ToString(), certString, misc.ToCompactBinary(&t.SystemStore)})
		if err != nil {
			log.Err(err).Msg("Error writing Certificate to file")
		}
		certCache.MarkOld(t.Cert)
	}
	return nil
}
