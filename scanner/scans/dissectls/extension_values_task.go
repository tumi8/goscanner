package dissectls

import (
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"golang.org/x/crypto/cryptobyte"
	"sort"
	"strconv"
	"strings"
)

type ExtensionValueTask struct {
	points [][]uint8
}

func (c *ExtensionValueTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
}

func (c *ExtensionValueTask) Done(model *results.ServerModel) bool {
	return false
}

func (c *ExtensionValueTask) ResolveError(*results.ServerModel) (learnedSomething bool) { return }

func (c *ExtensionValueTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	if state.ServerHello != nil && len(state.ServerHello.SupportedPoints) > 0 {
		var p []string
		for _, p_i := range state.ServerHello.SupportedPoints {
			p = append(p, strconv.Itoa(int(p_i)))
		}
		points := strings.Join(p, "-")
		present := false
		for _, m := range model.SupportedPoints {
			if m == points {
				present = true
			}
		}
		if !present {
			model.SupportedPoints = append(model.SupportedPoints, points)
			sort.Strings(model.SupportedPoints)
		}
	}

	for _, extSlice := range [][]tls.Extension{state.ServerExtensions, state.ServerEncryptedExtensions, state.CertificateExtensions} {
		for _, ext := range extSlice {
			var extData cryptobyte.String
			extData = ext.Data
			if ext.Extension == tls.ExtensionSignatureAlgorithms {
				var sigAndAlgs cryptobyte.String
				if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
					continue
				}
				for !sigAndAlgs.Empty() {
					var sigAndAlg uint16
					if !sigAndAlgs.ReadUint16(&sigAndAlg) {
						continue
					}
					present := false
					for _, m := range model.SupportedSignaturealgorithms {
						if m == sigAndAlg {
							present = true
						}
					}
					if !present {
						model.SupportedSignaturealgorithms = append(model.SupportedSignaturealgorithms, sigAndAlg)
						sort.Slice(model.SupportedSignaturealgorithms, func(i, j int) bool {
							return model.SupportedSignaturealgorithms[i] < model.SupportedSignaturealgorithms[j]
						})
					}
				}
			} else if ext.Extension == tls.ExtensionSignatureAlgorithmsCert {
				var sigAndAlgs cryptobyte.String
				if !extData.ReadUint16LengthPrefixed(&sigAndAlgs) || sigAndAlgs.Empty() {
					continue
				}
				for !sigAndAlgs.Empty() {
					var sigAndAlg uint16
					if !sigAndAlgs.ReadUint16(&sigAndAlg) {
						continue
					}
					present := false
					for _, m := range model.SupportedSignaturealgorithmsCert {
						if m == sigAndAlg {
							present = true
						}
					}
					if !present {
						model.SupportedSignaturealgorithmsCert = append(model.SupportedSignaturealgorithmsCert, sigAndAlg)
						sort.Slice(model.SupportedSignaturealgorithmsCert, func(i, j int) bool {
							return model.SupportedSignaturealgorithmsCert[i] < model.SupportedSignaturealgorithmsCert[j]
						})
					}
				}
			} else if ext.Extension == tls.ExtensionCertificateAuthorities {
				var auths cryptobyte.String
				if !extData.ReadUint16LengthPrefixed(&auths) || auths.Empty() {
					continue
				}
				for !auths.Empty() {
					var ca cryptobyte.String
					if !auths.ReadUint16LengthPrefixed(&ca) || len(ca) == 0 {
						continue
					}
					caString := string(ca)
					present := false
					for _, m := range model.CertificateAuthorities {
						if m == caString {
							present = true
						}
					}
					if !present {
						model.CertificateAuthorities = append(model.CertificateAuthorities, caString)
						sort.Strings(model.CertificateAuthorities)
					}
				}
			}
		}
	}

	return
}

func (c *ExtensionValueTask) PostProcess(*results.ServerModel) {}
