package scans

import (
	"github.com/pkg/errors"
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/scanner/scans/dissectls"
	"github.com/tumi8/goscanner/tls"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"io"
	"net"
	"strconv"
	"time"
)

type DeepTLSTask interface {
	// Done return whether the task has collected every information and is finished
	Done(model *results.ServerModel) bool
	// SetCHValues modifies the Client Hello preset depending on the current state model. scanDoneRate is an indicator
	// how many requests we can still perform depending on the Client Hellos we still have chsLeft. If playSafe is true,
	// the method should only set values where we are sure the server will successfully respond.
	SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int)
	// MergeData updates the model depending on the server response state or err
	MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool)
	// ResolveError will only be called if this task was responsible for the error and the task should resolve it.
	ResolveError(model *results.ServerModel) (learnedSomething bool)
	// PostProcess will be called after the scan is done
	PostProcess(model *results.ServerModel)
}

type DissecTLSScan struct {
	mode        string
	maxCHs      int
	scanCiphers []uint16
	scanALPN    []string
	scanGroups  []tls.CurveID
	qps         float64
	detailed    bool
	keylogFile  io.Writer
}

func (s *DissecTLSScan) GetDefaultPort() int {
	return 443
}

func (s *DissecTLSScan) Init(opts *misc.Options, keylogFile io.Writer) {
	s.mode = opts.DissecTLSMode
	s.maxCHs = opts.DissecTLSMaxCHs
	s.qps = opts.DissecTLSQps
	s.keylogFile = keylogFile
	s.detailed = !opts.DissecTLSLightweight
	log.Debug().Str("Ciphers", s.mode).Int("MaximumClientHellos", s.maxCHs).Float64("QPS", s.qps).Msg("DeepTLS: Config values")
	if s.mode == "recommended" {
		s.scanCiphers = []uint16{
			uint16(0xd005), // TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256
			uint16(0xd002), // TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384
			uint16(0xd001), // TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256
			uint16(0xccad), // TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256
			uint16(0xccac), // TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
			uint16(0xccaa), // TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			uint16(0xc0a7), // TLS_DHE_PSK_WITH_AES_256_CCM
			uint16(0xc0a6), // TLS_DHE_PSK_WITH_AES_128_CCM
			uint16(0xc09f), // TLS_DHE_RSA_WITH_AES_256_CCM
			uint16(0xc09e), // TLS_DHE_RSA_WITH_AES_128_CCM
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			uint16(0x1304), // TLS_AES_128_CCM_SHA256
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			uint16(0x00ab), // TLS_DHE_PSK_WITH_AES_256_GCM_SHA384
			uint16(0x00aa), // TLS_DHE_PSK_WITH_AES_128_GCM_SHA256
			uint16(0x009f), // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
			uint16(0x009e), // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
		}
		s.scanGroups = []tls.CurveID{
			tls.X25519,
			tls.CurveP384,
			tls.CurveP256,
			tls.CurveID(30),
		}
		s.scanALPN = dissectls.ScannerALPN
	} else if s.mode == "go" {
		s.scanCiphers = dissectls.ScannerSupportedCiphers
		s.scanGroups = dissectls.ScannerSupportedGroups
		s.scanALPN = dissectls.ScannerALPN
	} else if s.mode == "all" {
		s.scanALPN = []string{"http/0.9", "http/1.0", "http/1.1", "spdy/1", "spdy/2", "spdy/3", "stun.turn", "stun.nat-discovery", "h2", "h2c", "webrtc", "c-webrtc", "ftp", "imap", "pop3", "managesieve", "coap", "xmpp-client", "xmpp-server", "acme-tls/1", "mqtt", "dot", "ntske/1", "sunrpc", "h3", "smb", "irc"}
		s.scanGroups = []tls.CurveID{33, 32, 5, 31, 16, 60138, 26, 36, 28, 10, 12, 4, 21, 22, 39578, 13, 259, 65281, 1, 38, 6, 256, 3, 51914, 27, 7, 19018, 35466, 27242, 20, 10794, 34, 6682, 47802, 41, 25, 31354, 8, 9, 19, 257, 43690, 260, 24, 35, 2570, 15, 30, 17, 29, 11, 258, 64250, 2, 14906, 39, 40, 14, 37, 23, 65282, 23130, 18, 56026}
		s.scanCiphers = []uint16{49309, 49161, 49167, 52395, 49298, 45, 49297, 49196, 49263, 43, 49255, 49192, 49414, 49177, 49317, 49302, 49327, 49273, 49329, 49291, 49174, 41, 140, 4, 49271, 70, 49170, 53250, 108, 176, 49208, 49159, 13, 188, 161, 25, 146, 49277, 49239, 49287, 44, 49254, 169, 58, 52393, 48, 49224, 60, 136, 141, 156, 134, 34, 49274, 4869, 154, 49230, 49260, 49226, 49308, 32, 49195, 144, 49408, 40, 55, 49186, 49262, 36, 49162, 49215, 49222, 2, 51, 49306, 67, 49290, 49164, 49189, 49313, 49225, 59, 191, 168, 49153, 172, 174, 49232, 24, 49294, 49228, 198, 107, 49304, 49253, 49310, 173, 18, 190, 52, 49322, 147, 22, 8, 49320, 49240, 49210, 195, 164, 49286, 49199, 49295, 49238, 49411, 157, 49268, 166, 19, 38, 49328, 49303, 49281, 4866, 49319, 152, 49216, 63, 47, 49158, 49168, 49182, 49241, 49314, 26, 49244, 49184, 49307, 49325, 49275, 171, 49188, 49305, 49223, 159, 12, 187, 49212, 196, 21, 49251, 49198, 49323, 186, 50, 5, 37, 49202, 1, 151, 52398, 49227, 49316, 49292, 7, 49214, 49163, 193, 165, 49288, 56, 33, 20, 49248, 17, 49243, 49165, 49266, 49279, 52394, 49245, 46, 184, 49180, 49258, 49285, 49330, 49301, 14, 132, 49333, 49204, 135, 49250, 53249, 49, 49269, 53253, 143, 52243, 49249, 49278, 49282, 49203, 49201, 49169, 49221, 49176, 30, 49154, 49234, 138, 49157, 150, 49236, 182, 15, 145, 49171, 49289, 49252, 49259, 11, 49237, 49412, 49229, 42, 49331, 49179, 49296, 65, 27, 49166, 49315, 49280, 197, 49265, 163, 4867, 49235, 181, 49172, 49413, 62, 105, 175, 137, 53, 155, 0, 49160, 49205, 16, 199, 189, 149, 4865, 158, 162, 49178, 53251, 179, 49231, 49211, 49267, 35, 49324, 49270, 49156, 49206, 66, 49218, 180, 49190, 68, 148, 49175, 52392, 57, 49246, 49173, 106, 49256, 64, 49197, 49321, 177, 49242, 49299, 49276, 49284, 52396, 153, 6, 170, 49311, 3, 49209, 192, 54, 160, 49233, 49194, 49261, 104, 49155, 9, 49219, 103, 49272, 49185, 69, 49257, 49200, 49326, 49181, 49207, 49213, 49410, 185, 142, 49283, 49217, 139, 49247, 109, 31, 4868, 183, 61, 49191, 52244, 49264, 10, 49183, 23, 49193, 133, 39, 49187, 49300, 167, 49220, 49409, 178, 49318, 49293, 52397, 49332, 194, 49312}
	} else {
		log.Fatal().Str("Set", s.mode).Strs("Options", []string{"recommended", "go", "all"}).Msg("No valid parameter set")
	}
}

func (s *DissecTLSScan) Scan(conn net.Conn, target *Target, result *results.ScanResult, timeout time.Duration, synStart time.Time, synEnd time.Time, limiter *rate.Limiter) (net.Conn, error) {
	serverName := target.Domain

	ctx, cancel := context.WithCancel(context.Background())
	var err error
	_, ok := conn.(*tls.Conn)
	if ok {
		conn, _, _, err = reconnectContext(ctx, conn, timeout)
		if err != nil {
			return nil, errors.Wrap(err, "DeepTLS: Error occurred for initial reconnect")
		}
	}

	scanTasks := []DeepTLSTask{
		&dissectls.CipherTask{ScanCiphers: s.scanCiphers},
		&dissectls.SupportedGroupsTask{Groups: s.scanGroups},
		&dissectls.AlpnTask{ALPNs: s.scanALPN},
		&dissectls.ExtensionTask{},
		&dissectls.VersionTask{DetailedScan: s.detailed},
		&dissectls.FallbackTask{},
		&dissectls.EMSTask{},
		&dissectls.OCSPTask{},
		&dissectls.HeartbeatTask{},
		&dissectls.FragmentationTask{},
		&dissectls.ETMTask{},
		&dissectls.ExtensionValueTask{},
		&dissectls.AlertTask{},
	}
	model := results.ServerModel{}
	numRequests := 0
	var errorTasks []int
	tlsTimeouts := 0
	totalTimeouts := 0
	informationCut := false
	timeoutCut := false
	tcpError := false
	limiterHost := rate.NewLimiter(rate.Limit(s.qps), 1)
	for true {
		numRequests++
		preset := tls.ClientHelloPreset{
			Ciphers:             s.scanCiphers,
			CompressionMethods:  []uint8{0},
			RenegotiationInfo:   true,
			Renegotiation:       tls.RenegotiateOnceAsClient,
			Sct:                 true,
			SessionTicket:       true,
			EcPointFormats:      []uint8{0},
			PskKeyExchangeModes: []uint8{1},
			SupportedGroups:     dissectls.ScannerSupportedGroups,
			SignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP256AndSHA256,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.PSSWithSHA384,
				tls.PKCS1WithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA512,
			},
		}

		requestsDone := float64(numRequests) / float64(s.maxCHs)
		for i := range scanTasks {
			if !scanTasks[i].Done(&model) {
				playSafe := false
				if errorTasks != nil && len(errorTasks) > 1 {
					for _, p := range errorTasks[1:] {
						if p == i {
							playSafe = true
						}
					}
				}
				scanTasks[i].SetCHValues(&preset, &model, requestsDone, playSafe, s.maxCHs-numRequests)
			}
		}
		cache := tls.NewLRUClientSessionCache(1)

		tlsConn, err := scanTLS(conn, serverName, timeout, 0, cache, nil, nil, "", s.keylogFile, &preset)
		if tlsConn == nil {
			informationCut = true
			tcpError = true
			break
		}
		connectionState := tlsConn.ConnectionState()
		learnedNewStuff := false
		var newErrorTasks []int
		for i := range scanTasks {
			if !scanTasks[i].Done(&model) {
				errorWasTask, learned := scanTasks[i].MergeData(connectionState, &model, &preset, err)
				learnedNewStuff = learnedNewStuff || learned
				if errorWasTask {
					safeError := true
					if errorTasks != nil && len(errorTasks) > 1 {
						for _, p := range errorTasks[1:] {
							if i == p {
								// Was a playsafe task
								safeError = false
							}
						}
					}
					if safeError {
						newErrorTasks = append(newErrorTasks, i)
					}
				}
			}
		}

		// Handle Errors
		if len(newErrorTasks) == 1 {
			if scanTasks[newErrorTasks[0]].ResolveError(&model) {
				learnedNewStuff = true
			}
			// Play Safe disable
			if len(errorTasks) > 0 {
				errorTasks = nil
			}
		}
		if len(newErrorTasks) == 0 && len(errorTasks) > 1 {
			// Remove one playsafe task
			errorTasks = errorTasks[1:]
			learnedNewStuff = true
		}
		if len(newErrorTasks) > 1 {
			existingErrors := len(errorTasks)
			for _, e := range newErrorTasks {
				present := false
				for _, e2 := range errorTasks {
					if e == e2 {
						present = true
					}
				}
				if !present {
					errorTasks = append(errorTasks, e)
				}
			}
			if len(errorTasks) > existingErrors {
				learnedNewStuff = true
			}
		}
		if err != nil {
			handshakeError := results.HandshakeErrorLookup(err)
			if handshakeError == "TIMEOUT" {
				if tlsTimeouts >= 3 {
					informationCut = true
					timeoutCut = true
					log.Debug().Str("IP", target.Ip).Str("DN", target.Domain).Msg("DeepTLS: No retries left")
					cancel()
					break
				}
				time.Sleep(time.Second * 2)
				tlsTimeouts++
				totalTimeouts++
				numRequests--
				learnedNewStuff = true
			} else {
				var tasks []string
				for i, t := range scanTasks {
					if !t.Done(&model) {
						tasks = append(tasks, strconv.Itoa(i))
					}
				}
				log.Debug().Err(err).Strs("TasksLeft", tasks).Int("CHs", numRequests).Str("IP", target.Ip).Str("DN", target.Domain).Msg("DeepTLS: Error occurred")
				tlsTimeouts = 0
			}
		} else {
			tlsTimeouts = 0
		}

		if !learnedNewStuff {
			log.Debug().Str("IP", target.Ip).Str("DN", target.Domain).Int("CHs", numRequests).Msg("DeepTLS: Stopping, because no new information learned")
			break
		}

		if numRequests >= s.maxCHs {
			informationCut = true
			conn = tlsConn
			break
		} else {
			// Only send close if the connection is not already closed because of an alert (If connectionState.Errors != nil we did not really send the alerts)
			alreadyClosed := len(connectionState.RecvAlerts) > 0 || (len(connectionState.SendAlerts) > 0 && len(connectionState.Errors) == 0)
			if !alreadyClosed {
				err2 := tlsConn.Close()
				if err2 != nil && !misc.IsClosedConnErr(err2) {
					log.Err(err2).AnErr("PreviousErr", err).Str("IP", target.Ip).Str("DN", target.Domain).Msg("DeepTLS: Error closing connection")
				}
			}

			// Free resources
			cancel()
			ctx, cancel = context.WithCancel(context.Background())

			n := 0
			for true {
				if s.qps > 0 {
					_ = limiterHost.Wait(ctx)
				}
				_ = limiter.Wait(ctx)

				var conn2 net.Conn
				conn2, _, _, err = reconnectContext(ctx, conn, timeout)
				if err != nil {
					handshakeError := results.HandshakeErrorLookup(err)
					if handshakeError == "TIMEOUT" {
						totalTimeouts++
						n++
						if n >= 3 {
							timeoutCut = true
							break
						}
						time.Sleep(time.Second * 2)
						continue
					}
				} else {
					conn = conn2
				}
				break
			}
			if err != nil {
				log.Debug().Err(err).Msg("DeepTLS: Error occurred at reconnect")
				informationCut = true
				tcpError = true
				break
			}
		}
	}

	for _, t := range scanTasks {
		t.PostProcess(&model)
	}

	result.AddResult(results.ScanSubResult{
		SynStart: synStart,
		SynEnd:   synEnd,
		ScanEnd:  time.Now().UTC(),
		Result: results.DissecTLSResult{
			Model:          model,
			NumRequests:    numRequests,
			NumTimeouts:    totalTimeouts,
			InformationCut: informationCut,
			Timeout:        timeoutCut,
			TcpError:       tcpError,
		},
	})

	return conn, nil
}
