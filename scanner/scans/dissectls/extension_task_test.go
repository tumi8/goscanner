package dissectls

import (
	"github.com/tumi8/goscanner/tls"
	"reflect"
	"testing"
)

func Test_applyToModelSingle(t *testing.T) {
	type testCases struct {
		name       string
		input      [][]uint16
		result     [][]uint16
		consistent bool
	}
	tests := []testCases{
		{"simple chain", [][]uint16{{1, 2, 3}, {3, 4, 5}, {2, 3, 4}}, [][]uint16{{1, 2, 3, 4, 5}}, true},
		{"transitive edges", [][]uint16{{1, 3, 4}, {1, 2, 3}}, [][]uint16{{1, 2, 3, 4}}, true},
		{"inconsistent edges", [][]uint16{{2, 3, 4, 1}, {3, 4, 2, 1}}, [][]uint16{{1, 2, 3, 4}}, false},
		{"multiple chains", [][]uint16{{1, 2, 3}, {7, 8, 9}, {1, 2, 5}, {6, 2, 3}}, [][]uint16{{1, 2, 3}, {6, 2, 3}, {1, 2, 5}, {6, 2, 5}, {7, 8, 9}}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var graph []*extensionDependencyNode
			for _, extensions := range tt.input {
				var inputExtensions []tls.Extension
				for _, ext := range extensions {
					inputExtensions = append(inputExtensions, tls.Extension{Extension: ext})
				}
				extractExtensionDependencies(inputExtensions, &graph)
			}

			// Process Graph
			var result [][]uint16
			consistent := applyToModelSingle(&graph, &result)

			if !reflect.DeepEqual(result, tt.result) {
				t.Errorf("Error in result, should be %v but was %v", tt.result, result)
			}
			if tt.consistent != consistent {
				t.Errorf("Graph was %v but test reported %v", tt.consistent, consistent)
			}
		})
	}
}
