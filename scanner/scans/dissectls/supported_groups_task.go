package dissectls

import (
	"github.com/rs/zerolog/log"
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"golang.org/x/crypto/cryptobyte"
	"sort"
	"strings"
)

type SupportedGroupsTask struct {
	Groups                     []tls.CurveID
	scannableGroups            []tls.CurveID
	lastGroup                  tls.CurveID
	scanForPreference          bool
	isDone                     bool
	preferClient               *bool
	preferClientWithKey        *bool
	preferenceScanDone         bool
	scanWithKeyShare           bool
	scanWithKeyShareImpossible bool
	scanForNextGroup           bool

	force13          bool
	forceECDH        bool
	ecdhCipherWorks  uint16
	unsupportedCurve bool
	errorBehavior    string
}

var tls13Ciphers = []uint16{tls.TLS_AES_128_GCM_SHA256, tls.TLS_AES_256_GCM_SHA384, tls.TLS_CHACHA20_POLY1305_SHA256}

var ScannerSupportedGroups = []tls.CurveID{tls.CurveP256, tls.X25519, tls.CurveP384, tls.CurveP521}

func (c *SupportedGroupsTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
	c.scanForPreference = (c.preferClient == nil || c.preferClientWithKey == nil) &&
		(c.isDone || len(model.SupportedGroupsPrio) >= len(c.Groups) || scanDoneRate > 0.6) && len(model.SupportedGroupsPrio) > 1

	if playSafe && c.preferClient == nil && len(model.SupportedGroupsPrio) > 1 {
		// If we have to play safe anyway we can also scan for preference
		c.scanForPreference = true
	}

	// Full preferences default
	preset.SupportedGroups = c.Groups
	// If I know 13 works and we would scan < 13 => force 13
	c.force13 = model.VersionTLS13 != nil && *model.VersionTLS13 == "True" && preset.Version < tls.VersionTLS13 && !playSafe
	// If I know ECDH ciphers work => force this cipher
	c.forceECDH = preset.Version < tls.VersionTLS13 && !c.force13 && c.ecdhCipherWorks > 0 && !playSafe

	c.scanForNextGroup = (preset.Version == tls.VersionTLS13 || c.force13 || c.forceECDH) && (c.scanForPreference || !playSafe)

	c.scanWithKeyShare = c.scanForNextGroup && c.scanForPreference && c.preferClientWithKey == nil && !c.scanWithKeyShareImpossible

	if c.scanForNextGroup {
		preset.SupportedGroups = nil

		for i := range c.Groups {
			scanned := false
			for j := range model.SupportedGroupsPrio {
				if c.Groups[i] == model.SupportedGroupsPrio[j] {
					scanned = true
				}
			}
			if !scanned || (playSafe && !c.scanForPreference) {
				preset.SupportedGroups = append(preset.SupportedGroups, c.Groups[i])
			}
		}
		if c.scanForPreference {
			if c.scanWithKeyShare {
				preset.SupportedGroups = []tls.CurveID{c.scannableGroups[1], c.scannableGroups[0]}
				c.lastGroup = c.scannableGroups[1]
				preset.KeyShares = 1
			} else if c.isDone {
				preset.SupportedGroups = []tls.CurveID{model.SupportedGroupsPrio[1], model.SupportedGroupsPrio[0]}
				c.lastGroup = model.SupportedGroupsPrio[1]
			} else {
				preset.SupportedGroups = append(preset.SupportedGroups, c.lastGroup, model.SupportedGroupsPrio[0])
			}
		}
	}

	if c.force13 {
		// Enable TLS 13
		preset.Version = tls.VersionTLS13
		model.ScanKnownCipher = true

		for _, c1 := range tls13Ciphers {
			present := false
			for _, c2 := range preset.Ciphers {
				if c1 == c2 {
					present = true
				}
			}
			if !present {
				preset.Ciphers = append(preset.Ciphers, c1)
			}
		}
	}

	if c.forceECDH {
		model.ScanKnownCipher = true
		preset.Ciphers = []uint16{c.ecdhCipherWorks}
	}
}

func (c *SupportedGroupsTask) Done(model *results.ServerModel) bool {

	c.scannableGroups = nil
	// Can I scan with keyshare?
	for _, g := range model.SupportedGroupsPrio {
		for _, g2 := range ScannerSupportedGroups {
			if g == g2 {
				c.scannableGroups = append(c.scannableGroups, g)
			}
		}
	}
	c.scanWithKeyShareImpossible = len(c.scannableGroups) <= 1 || (model.VersionTLS13 != nil && *model.VersionTLS13 != "True")

	return c.isDone && (c.preferenceScanDone || (c.preferClient != nil && (c.scanWithKeyShareImpossible || c.preferClientWithKey != nil)))
}

func (c *SupportedGroupsTask) ResolveError(model *results.ServerModel) (learnedSomething bool) {
	if !c.unsupportedCurve {
		learnedSomething = !c.isDone
		c.preferenceScanDone = len(model.SupportedGroupsPrio) <= 1 || c.isDone
		c.isDone = true
	}
	if c.errorBehavior != "" {
		if model.GroupsError != nil && c.errorBehavior != *model.GroupsError {
			log.Debug().Str("ErrorBehavior", c.errorBehavior).Str("OldError", *model.GroupsError).Msg("Contradicting GroupsError Behaviors")
		}
		e := c.errorBehavior
		model.GroupsError = &e
	}
	return
}

func (c *SupportedGroupsTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	c.unsupportedCurve = false
	c.errorBehavior = ""
	var selectedGroup tls.CurveID
	for _, extSlice := range [][]tls.Extension{state.ServerExtensions, state.ServerEncryptedExtensions} {
		for _, ext := range extSlice {
			if ext.Extension == tls.ExtensionKeyShare {
				data := cryptobyte.String(ext.Data)
				var group uint16
				if !data.ReadUint16(&group) {
					continue
				}
				selectedGroup = tls.CurveID(group)

			} else if ext.Extension == tls.ExtensionSupportedCurves {
				var supportedGroupsPrio []tls.CurveID
				extData := cryptobyte.String(ext.Data)
				done := true
				var curves cryptobyte.String
				if !extData.ReadUint16LengthPrefixed(&curves) || curves.Empty() {
					done = false
				}
				for done && !curves.Empty() {
					var curve uint16
					if !curves.ReadUint16(&curve) {
						done = false
						break
					}
					supportedGroupsPrio = append(supportedGroupsPrio, tls.CurveID(curve))
				}

				if done {
					model.SupportedGroupsPrio = supportedGroupsPrio
					learnedSomething = true
					c.isDone = true
				}
			}
		}
	}

	if selectedGroup == 0 && state.Pre13ECDHParams > 0 {
		c.ecdhCipherWorks = state.ServerHello.CipherSuite
		selectedGroup = state.Pre13ECDHParams
	}

	// Merge Selected Group into Model
	if selectedGroup > 0 && !c.isDone {
		addGroup := true
		for _, s := range model.SupportedGroupsPrio {
			// same cipher could be caused by scanForPreference or other task
			if s == selectedGroup {
				addGroup = false
			}
		}
		if addGroup {
			model.SupportedGroupsPrio = append(model.SupportedGroupsPrio, selectedGroup)
			learnedSomething = true
		}
		didSentGroup := false
		for _, s := range preset.SupportedGroups {
			if s == selectedGroup {
				didSentGroup = true
			}
		}
		if !didSentGroup {
			model.IgnoresGroups = misc.NewTrue()
		}

		if !addGroup && c.scanForNextGroup && !c.scanForPreference {
			// Server is weird and selects a group we did not announce
			c.isDone = true
			c.preferenceScanDone = true
			learnedSomething = true
		}
	}
	if !c.preferenceScanDone && selectedGroup > 0 && c.scanForPreference {

		if c.scanWithKeyShare && model.PreferClientGroupsWithKeyShare == nil {
			if selectedGroup == c.lastGroup {
				c.preferClientWithKey = misc.NewTrue()
			} else {
				c.preferClientWithKey = misc.NewFalse()
			}
			model.PreferClientGroupsWithKeyShare = c.preferClientWithKey
			learnedSomething = true
		} else if model.PreferClientGroups == nil {
			if selectedGroup == c.lastGroup {
				c.preferClient = misc.NewTrue()
			} else {
				c.preferClient = misc.NewFalse()
			}
			model.PreferClientGroups = c.preferClient
			learnedSomething = true
		}
	}
	if selectedGroup > 0 {
		c.lastGroup = selectedGroup
	}

	if !c.isDone && model.PreferClientGroups == nil {
		i := 0
		j := 0
		for j < len(model.SupportedGroupsPrio) {
			if c.Groups[i] == model.SupportedGroupsPrio[j] {
				i++
				j++
			} else {
				i++
			}
			if i >= len(c.Groups) && j < len(model.SupportedGroupsPrio) {
				model.PreferClientGroups = misc.NewFalse()
				c.preferClient = model.PreferClientGroups
				learnedSomething = true
				break
			}
		}
	}

	// Eventually finish this task
	if (c.force13 || c.forceECDH) && state.ServerHello != nil && selectedGroup == 0 {
		learnedSomething = !c.isDone

		if model.GroupsError == nil && !c.isDone {
			e := "Ignore"
			model.GroupsError = &e
		}

		c.isDone = true
		if c.scanForPreference {
			learnedSomething = learnedSomething || !c.preferenceScanDone
			c.preferenceScanDone = true
		}
	}

	// Error handling
	for _, e := range state.Errors {
		if strings.Contains(e.Error(), "server selected unsupported curve") {
			errorCouldBeMe = true
			c.unsupportedCurve = true
		}
	}
	if c.scanForNextGroup {
		for _, e := range state.RecvAlerts {
			if e == 40 {
				errorCouldBeMe = true
				c.errorBehavior = "Alert"
			}
		}
		if strangeErrorHandlingPossible(err) {
			errorCouldBeMe = true
			c.errorBehavior = "TCP"
		}
		if len(state.SendAlerts) > 0 && (err == nil || !strings.Contains(err.Error(), "unconfigured cipher")) {
			errorCouldBeMe = true
		}
	}

	return
}

func (c *SupportedGroupsTask) PostProcess(model *results.ServerModel) {
	if model.PreferClientGroups != nil && *model.PreferClientGroups {
		sort.Slice(model.SupportedGroupsPrio, func(i, j int) bool {
			return model.SupportedGroupsPrio[i] < model.SupportedGroupsPrio[j]
		})
	}
	if c.isDone && len(model.SupportedGroupsPrio) > 0 {
		model.SupportedGroupsDone = misc.NewTrue()
	}
}
