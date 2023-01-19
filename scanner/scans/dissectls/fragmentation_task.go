package dissectls

import (
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"math"
)

type FragmentationTask struct {
	maxFragmentDone     bool
	recordSizeLimitDone bool
}

func (c *FragmentationTask) SetCHValues(preset *tls.ClientHelloPreset, model *results.ServerModel, scanDoneRate float64, playSafe bool, chsLeft int) {
	if !c.recordSizeLimitDone && model.RecordSizeLimitSupport == nil {
		// Values range from 64 - 2^14
		preset.RecordSizeLimit = uint16(math.Pow(2, 13))
		c.recordSizeLimitDone = true
	} else if !c.maxFragmentDone && model.MaxFragmentSizeSupport == nil {
		// Try for < TLS 1.3
		// Values fo from 1-4
		preset.MaxFragmentLength = 3
		c.maxFragmentDone = true
	}
}

func (c *FragmentationTask) Done(model *results.ServerModel) bool {
	return model.MaxFragmentSizeSupport != nil && model.RecordSizeLimitSupport != nil
}

func (c *FragmentationTask) ResolveError(model *results.ServerModel) (learnedSomething bool) {
	if c.maxFragmentDone && model.MaxFragmentSizeSupport == nil {
		model.MaxFragmentSizeSupport = misc.NewTrue()
		learnedSomething = true
	} else if c.recordSizeLimitDone && model.RecordSizeLimitSupport == nil {
		model.RecordSizeLimitSupport = misc.NewTrue()
		learnedSomething = true
	}
	return
}

func (c *FragmentationTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	for _, extSlice := range [][]tls.Extension{state.ServerExtensions, state.ServerEncryptedExtensions} {
		for _, ext := range extSlice {
			if ext.Extension == tls.ExtensionMaxFragmentLength {
				learnedSomething = model.MaxFragmentSizeSupport == nil
				model.MaxFragmentSizeSupport = misc.NewTrue()
			} else if ext.Extension == tls.ExtensionRecordSizeLimit {
				learnedSomething = model.RecordSizeLimitSupport == nil
				model.RecordSizeLimitSupport = misc.NewTrue()
			}
		}
	}
	for _, e := range state.RecvAlerts {
		if e == 22 || e == 47 {
			errorCouldBeMe = true
		}
	}
	if state.ServerHello != nil {
		if c.recordSizeLimitDone && model.RecordSizeLimitSupport == nil {
			learnedSomething = true
			model.RecordSizeLimitSupport = misc.NewFalse()
		}
		if c.maxFragmentDone && model.MaxFragmentSizeSupport == nil {
			learnedSomething = true
			model.MaxFragmentSizeSupport = misc.NewFalse()
		}
	}
	return
}

func (c *FragmentationTask) PostProcess(*results.ServerModel) {}
