package results

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/hex"
	log "github.com/sirupsen/logrus"
	"github.com/tumi8/goscanner/scanner/misc"
	"time"
)

const beginPublicKey = "-----BEGIN PUBLIC KEY-----"
const endPublicKey = "-----END PUBLIC KEY-----"
// beginCertificate and endCertificate signal start and beginning of PEM-encoded TLS certificates
const beginCertificate = "-----BEGIN CERTIFICATE-----"
const endCertificate = "-----END CERTIFICATE-----"
var certCsvHeader = []string{"cert", "cert_hash"}

type CertResult struct {
	Depth	int
	Cert	*x509.Certificate
}

func (t *CertResult) GetCsvFileName() string {
	return FileCerts
}

func (t *CertResult) GetCsvHeader() []string {
	return certCsvHeader
}

func (t *CertResult)  WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool,  cacheFunc func([]byte) []byte, cache map[string]map[string]struct{}) {
	sha256Hex := hex.EncodeToString(misc.GetSHA256(t.Cert.Raw))

	if cacheFunc != nil {
		// Check if certificate was already written out before
		// Use byte string as map key to save memory (slices can not be used as map key)
		cacheBytes := string(cacheFunc(t.Cert.Raw))

		_, ok := cache[cacheBytes[:1]]

		if !ok {
			cache[cacheBytes[:1]] = make(map[string]struct{})
		}
		if _, ok := cache[cacheBytes[:1]][cacheBytes[1:]]; !ok {
			// Write row in cert CSV file
			// [cert, cert_hash]
			certString := misc.OpensslFormat(base64.StdEncoding.EncodeToString(t.Cert.Raw), beginCertificate, endCertificate)
			if ok := writer.Write([]string{certString, sha256Hex}); ok != nil {
				log.WithFields(log.Fields{
					"file": t.GetCsvFileName(),
				}).Error("Error writing to certificate file")
			} else {
				cache[cacheBytes[:1]][cacheBytes[1:]] = struct{}{}
			}
		}
	} else {
		// Write row in cert CSV file
		// [cert, cert_hash]
		certString := misc.OpensslFormat(base64.StdEncoding.EncodeToString(t.Cert.Raw), beginCertificate, endCertificate)
		if ok := writer.Write([]string{certString, sha256Hex}); ok != nil {
			log.WithFields(log.Fields{
				"file": t.GetCsvFileName(),
			}).Error("Error writing to certificate file")
		}
	}
}
