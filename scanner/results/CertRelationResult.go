package results

import (
	"crypto/x509"
	"encoding/csv"
	"encoding/hex"
	log "github.com/sirupsen/logrus"
	"github.com/tumi8/goscanner/scanner/misc"
	"net"
	"strconv"
	"time"
)

var chrCsvHeader = []string{"cert_hash", "host", "port", "server_name", "depth", "pub_key_hash"}

type CertRelationResult struct {
	Depth 	int
	Cert	*x509.Certificate
}


func (t *CertRelationResult) GetCsvFileName() string {
	return FileCertHostRel
}

func (t *CertRelationResult) GetCsvHeader() []string {
	return chrCsvHeader
}

func (t *CertRelationResult)   WriteCsv(writer *csv.Writer, parentResult *ScanResult, synStart time.Time, synEnd time.Time, scanEnd time.Time, skipErrors bool,  cacheFunc func([]byte) []byte, cache map[string]map[string]struct{}) {
	// Write to certificate-host relation CSV file
	ip, port, err := net.SplitHostPort(parentResult.Address)
	if err != nil {
		log.WithFields(log.Fields{
			"address": parentResult.Address,
		}).Error("Could not split address into host and port parts.")
	}

	sha256Hex := hex.EncodeToString(misc.GetSHA256(t.Cert.Raw))

	// [cert_hash, host, port, depth, pub_key_hash]
	sha256SPKI := hex.EncodeToString(misc.GetSHA256(t.Cert.RawSubjectPublicKeyInfo))

	if ok := writer.Write([]string{sha256Hex, ip, port, parentResult.Domain, strconv.Itoa(t.Depth), sha256SPKI}); ok != nil {
		log.WithFields(log.Fields{
			"file": t.GetCsvFileName(),
		}).Error("Error writing to host-certificate-relationship file")
	}
}