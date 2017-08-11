package scanner

import (
	"errors"
	"net"
	"strings"
	"time"

	"github.com/tumi8/ssh"
)

// SSHScanner implements the scanning of the SSH protocol
type SSHScanner struct {
	inputChan  chan *Target
	outputChan chan *Target
}

// NewSSHScanner returns an initialized SSHScanner struct
func NewSSHScanner() SSHScanner {
	// Create channels for input and output targets
	return SSHScanner{make(chan *Target, 10000), make(chan *Target)}
}

// dontAcceptHostKeyErr is a dummy error which is returned by key callback function to interrupt the SSH connection setup
var dontAcceptHostKeyErr = errors.New("dontAcceptHostKeyErr")

// keyCallback sends received host key to result channel
func (s SSHScanner) keyCallback(hostname string, remote net.Addr, key ssh.PublicKey) error {

	// don't accept HostKey to close the connection earlier and not appear too much in the logFiles
	return dontAcceptHostKeyErr
}

// scanSSH sets the correct host key callback function and establishes an SSH connection
func (s SSHScanner) scanSSH(conn net.Conn, timeout time.Duration) (*ssh.ServerInfo, error) {
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

// ScanProtocol performs the actual SSH scan and adds results to the target
func (s SSHScanner) ScanProtocol(conn net.Conn, host *Target, timeout time.Duration, synStart time.Time, synEnd time.Time) {
	serverInfo, err := s.scanSSH(conn, timeout)

	scanResult := &ScanResult{
		synStart: synStart,
		synEnd:   synEnd,
		scanEnd:  time.Now().UTC(),
	}

	var sshResult SSHResult
	if serverInfo != nil {
		split := strings.SplitN(serverInfo.ServerVersion, "-", 3)
		sshVersion, serverVersion := strings.Join(split[0:2], "-"), split[2]

		sshResult = SSHResult{
			sshVersion:               sshVersion,
			serverVersion:            serverVersion,
			hostKey:                  serverInfo.Key,
			fingerprint:              ssh.FingerprintSHA256(serverInfo.Key),
			macsClientServer:         serverInfo.ServerInit.MACsClientServer,
			macsServerClient:         serverInfo.ServerInit.MACsServerClient,
			ciphersClientServer:      serverInfo.ServerInit.CiphersClientServer,
			ciphersServerClient:      serverInfo.ServerInit.CiphersServerClient,
			serverHostKeyAlgos:       serverInfo.ServerInit.ServerHostKeyAlgos,
			kexAlgos:                 serverInfo.ServerInit.KexAlgos,
			compressionsClientServer: serverInfo.ServerInit.CompressionClientServer,
			compressionsServerClient: serverInfo.ServerInit.CompressionServerClient,
			languagesClientServer:    serverInfo.ServerInit.LanguagesClientServer,
			languagesServerClient:    serverInfo.ServerInit.LanguagesServerClient,
			err: nil,
		}
	}

	if !strings.Contains(err.Error(), dontAcceptHostKeyErr.Error()) {
		// Some error occurred - scan of IP failed
		sshResult.err = err
	}

	scanResult.result = sshResult
	(*host).AddResult(conn.RemoteAddr().String(), scanResult)
}

// InputChannel returns the input channel for reading and writing targets
func (s SSHScanner) InputChannel() chan *Target {
	return s.inputChan
}

// OutputChannel returns the output channel for reading and writing results
func (s SSHScanner) OutputChannel() chan *Target {
	return s.outputChan
}
