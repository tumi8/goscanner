package scans

import (
	"errors"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/ssh"
	"golang.org/x/time/rate"
	"io"
	"net"
	"strings"
	"time"
)

type SSHScan struct {
}

func (s *SSHScan) GetDefaultPort() int {
	return 22
}

func (s *SSHScan) Init(opts *misc.Options, keylogFile io.Writer) {}

func (s *SSHScan) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (net.Conn, error) {
	serverInfo, err := s.scanSSH(conn, timeout)

	scanResult := &results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
	}

	var sshResult results.SSHResult
	if serverInfo != nil && serverInfo.ServerVersion != "" {
		split := strings.SplitN(serverInfo.ServerVersion, "-", 3)

		var sshVersion, serverVersion string
		if len(split) == 3 {
			sshVersion, serverVersion = strings.Join(split[0:2], "-"), split[2]
		} else {
			sshVersion, serverVersion = "", serverInfo.ServerVersion
		}

		sshResult = results.SSHResult{
			SshVersion:               sshVersion,
			ServerVersion:            serverVersion,
			HostKey:                  serverInfo.Key,
			MacsClientServer:         serverInfo.ServerInit.MACsClientServer,
			MacsServerClient:         serverInfo.ServerInit.MACsServerClient,
			CiphersClientServer:      serverInfo.ServerInit.CiphersClientServer,
			CiphersServerClient:      serverInfo.ServerInit.CiphersServerClient,
			ServerHostKeyAlgos:       serverInfo.ServerInit.ServerHostKeyAlgos,
			KexAlgos:                 serverInfo.ServerInit.KexAlgos,
			CompressionsClientServer: serverInfo.ServerInit.CompressionClientServer,
			CompressionsServerClient: serverInfo.ServerInit.CompressionServerClient,
			LanguagesClientServer:    serverInfo.ServerInit.LanguagesClientServer,
			LanguagesServerClient:    serverInfo.ServerInit.LanguagesServerClient,
			Err:                      nil,
		}

		if serverInfo.Key != nil {
			sshResult.Fingerprint = ssh.FingerprintSHA256(serverInfo.Key)
		} else {
			sshResult.Fingerprint = ""
		}
	}

	if !strings.Contains(err.Error(), dontAcceptHostKeyErr.Error()) {
		// Some error occurred - scan of IP failed
		sshResult.Err = err
	}

	scanResult.Result = sshResult
	result.AddResult(*scanResult)
	return conn, nil
}

// dontAcceptHostKeyErr is a dummy error which is returned by key callback function to interrupt the SSH connection setup
var dontAcceptHostKeyErr = errors.New("dontAcceptHostKeyErr")

// keyCallback sends received host key to result channel
func (s SSHScan) keyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {

	// don't accept HostKey to close the connection earlier and not appear too much in the logFiles
	return dontAcceptHostKeyErr
}

// scanSSH sets the correct host key callback function and establishes an SSH connection
func (s SSHScan) scanSSH(conn net.Conn, timeout time.Duration) (*ssh.ServerInfo, error) {
	// SSH client config
	var sshConfig = &ssh.ClientConfig{
		HostKeyCallback:   s.keyCallback,
		ClientVersion:     "SSH-2.0-OpenSSH_Research_SSH_scanner",
		HostKeyAlgorithms: strings.Fields("ssh-rsa"),
		Timeout:           timeout,
	}

	// Establish SSH connection on top of TCP connection
	_, _, _, serverInfo, err := ssh.NewClientConn(conn, conn.RemoteAddr().String(), sshConfig)

	return serverInfo, err
}
