package dissectls

import (
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
)

type EMSTask struct {
}

func (c *EMSTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
	preset.ExtendedMasterSecret = model.ExtendedMasterSecret == nil
}

func (c *EMSTask) Done(model *results.ServerModel) bool {
	return model.ExtendedMasterSecret != nil
}

func (c *EMSTask) ResolveError(*results.ServerModel) (learnedSomething bool) { return }

func (c *EMSTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	for _, extSlice := range [][]tls.Extension{state.ServerExtensions} {
		for _, ext := range extSlice {
			if ext.Extension == tls.ExtensionExtendedMasterSecret {
				model.ExtendedMasterSecret = misc.NewTrue()
				learnedSomething = true
				errorCouldBeMe = true
			}
		}
	}
	if model.ExtendedMasterSecret == nil && state.ServerHello != nil && state.Version != tls.VersionTLS13 {
		model.ExtendedMasterSecret = misc.NewFalse()
		learnedSomething = true
	}
	return
}

func (c *EMSTask) PostProcess(*results.ServerModel) {}
