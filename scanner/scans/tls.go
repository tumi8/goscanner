package scans

import (
	"crypto/x509"
	"errors"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"io"
	"net"
	"time"
)

const beginCertificate = "-----BEGIN CERTIFICATE-----"
const endCertificate = "-----END CERTIFICATE-----"

type TLSScan struct {
	extendedTLSExport        bool
	saveStapledOCSPResponses bool
	keyLogFile               io.Writer
}

func (s *TLSScan) GetDefaultPort() int {
	return 443
}

func (s *TLSScan) Init(opts *misc.Options, keylogFile io.Writer) {
	s.extendedTLSExport = opts.TLSExtendedExport
	s.saveStapledOCSPResponses = opts.TLSSaveStapledOcspResponses
	s.keyLogFile = keylogFile
}

// Scan performs the actual TLS scan and adds results to the target
func (s *TLSScan) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (net.Conn, error) {
	serverName := target.Domain

	cache := tls.NewLRUClientSessionCache(1)

	tlsConn, err := scanTLS(conn, serverName, timeout, 0, cache, nil, nil, target.CHName, s.keyLogFile, nil)
	if tlsConn == nil {
		return nil, err
	}
	connectionState := tlsConn.ConnectionState()

	if s.extendedTLSExport {
		result.AddResult(results.ScanSubResult{
			SynStart: synStart,
			SynEnd:   synEnd,
			ScanEnd:  time.Now().UTC(),
			Result: &results.TLSFingerprintResult{
				TLSState: connectionState,
			},
		})
	}

	if err != nil {
		result.AddResult(results.ScanSubResult{
			SynStart: synStart,
			SynEnd:   synEnd,
			ScanEnd:  time.Now().UTC(),
			Result: &results.TLSResult{
				SendAlerts: connectionState.SendAlerts,
				RecvAlerts: connectionState.RecvAlerts,
				Errors:     connectionState.Errors,
				Err:        err,
			},
		})
		return conn, err
	} else {
		var leafCert *x509.Certificate

		for i, certificate := range connectionState.PeerCertificates {
			if leafCert == nil {
				leafCert = certificate
			}
			result.AddResult(results.ScanSubResult{
				SynStart: synStart,
				SynEnd:   synEnd,
				ScanEnd:  time.Now().UTC(),
				Result: &results.CertResult{
					Depth: i,
					Cert:  certificate,
				},
			})
		}

		if s.saveStapledOCSPResponses && connectionState.OCSPResponse != nil {
			result.AddResult(results.ScanSubResult{
				SynStart: synStart,
				SynEnd:   synEnd,
				ScanEnd:  time.Now().UTC(),
				Result: &results.StapledOCSPResult{
					OCSPResponseBytes: connectionState.OCSPResponse,
				},
			})
		}

		result.AddResult(results.ScanSubResult{
			SynStart: synStart,
			SynEnd:   synEnd,
			ScanEnd:  time.Now().UTC(),
			Result: &results.TLSResult{
				Certificate:     leafCert,
				AllCertificates: connectionState.PeerCertificates,
				Version:         connectionState.Version,
				Cipher:          connectionState.CipherSuite,
				SendAlerts:      connectionState.SendAlerts,
				RecvAlerts:      connectionState.RecvAlerts,
				Errors:          connectionState.Errors,
				Err:             err,
			},
		})

		// Find Certificate Chains
		pool := misc.NewCertPool(connectionState.PeerCertificates, true)
		systemStoreCallback := func(cert *x509.Certificate) {
			result.AddResult(results.ScanSubResult{
				SynStart: synStart,
				SynEnd:   synEnd,
				ScanEnd:  time.Now().UTC(),
				Result: &results.CertResult{
					Cert:        cert,
					SystemStore: true,
				},
			})
		}
		chains := findChains(leafCert, []x509.Certificate{*leafCert}, pool, systemStoreCallback)
		for i := range chains {
			result.AddResult(results.ScanSubResult{
				SynStart: synStart,
				SynEnd:   synEnd,
				ScanEnd:  time.Now().UTC(),
				Result:   &chains[i],
			})
		}
		return tlsConn, nil
	}
}

func scanTLS(conn net.Conn, serverName string, timeout time.Duration, maxVersion uint16, clientSessionCache tls.ClientSessionCache, ciphers []uint16, alpnProtocols []string, clientHello string, keyLogWriter io.Writer, clientHelloPreset *tls.ClientHelloPreset) (*tls.Conn, error) {
	customClientHello := misc.GetClientHello(clientHello)
	if clientHelloPreset != nil {
		customClientHello = clientHelloPreset
	}

	tlsConfig := &tls.Config{
		InsecureSkipVerify: true,
		// Use SNI if domain name is available
		ServerName: serverName,
		MaxVersion: maxVersion,
		// Use cache to speed up resumption for multiple HTTP requests
		ClientSessionCache: clientSessionCache,
		NextProtos:         alpnProtocols,
		ClientHelloPreset:  customClientHello,
		KeyShares:          1,
		KeyLogWriter:       keyLogWriter,
	}
	if ciphers != nil {
		tlsConfig.CipherSuites = ciphers
	}

	if conn == nil {
		log.Error().Str("ServerName", serverName).Msg("TCP Connection was nil")
		return nil, errors.New("TCP Connection was nil")
	}

	// Establish TLS connection on top of TCP connection
	tlsConn := tls.Client(conn, tlsConfig)
	now := time.Now()
	timePlusTimeout := now.Add(timeout)
	err := tlsConn.SetDeadline(timePlusTimeout)
	if err != nil {
		log.Debug().Err(err).Str("Address", conn.RemoteAddr().String()).Str("ServerName", serverName).Msg("Error while setting tls connection timeout")
	}
	err = tlsConn.Handshake()
	return tlsConn, err
}

// reconnect reestablishes the TCP connection
func reconnect(conn net.Conn, timeout time.Duration) (net.Conn, time.Time, time.Time, error) {
	return reconnectContext(context.Background(), conn, timeout)
}

func reconnectContext(ctx context.Context, conn net.Conn, timeout time.Duration) (net.Conn, time.Time, time.Time, error) {
	localAddr, _, _ := net.SplitHostPort((conn).LocalAddr().String())
	ip := (conn).RemoteAddr().String()
	// Close previous connection
	err := (conn).Close()
	if err != nil && !misc.IsClosedConnErr(err) {
		log.Debug().Err(err).Str("Address", ip).Msg("Error closing connection for reconnect")
	}

	synStart := time.Now().UTC()
	dialer := net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(localAddr)}}
	synEnd := time.Now().UTC()

	newConn, err := dialer.DialContext(ctx, "tcp", ip)

	return newConn, synStart, synEnd, err
}

func findChains(start *x509.Certificate, currentChain []x509.Certificate, all *misc.CertPool, callback func(certificate *x509.Certificate)) []results.CertRelationResult {
	foundChain := false
	var result []results.CertRelationResult
	if len(currentChain) > all.N() { // Loop
		return []results.CertRelationResult{{currentChain, results.NoRoot}}
	}
	possibleParents := all.FindPotentialParents(start)

outerLoop:
	for _, parentIndex := range possibleParents {
		parent := *all.Get(parentIndex)
		if parent.CheckSignature(start.SignatureAlgorithm, start.RawTBSCertificate, start.Signature) == nil {
			foundChain = true

			newChain := make([]x509.Certificate, len(currentChain)+1)
			copy(newChain, currentChain)
			newChain[len(currentChain)] = parent
			if parentIndex >= all.N() {
				result = append(result, results.CertRelationResult{Chain: newChain, Root: results.SystemStore})
				callback(&parent)
				continue outerLoop
			} else {
				for _, cert := range currentChain {
					if cert.Equal(&parent) {
						result = append(result, results.CertRelationResult{Chain: newChain, Root: results.Loop})
						continue outerLoop
					}
				}
				chains := findChains(&parent, newChain, all, callback)
				result = append(result, chains...)
			}
		}
	}
	if !foundChain {
		return []results.CertRelationResult{{currentChain, results.NoRoot}}
	} else {
		return result
	}
}
