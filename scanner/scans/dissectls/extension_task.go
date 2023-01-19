package dissectls

import (
	"github.com/tumi8/goscanner/scanner/misc"
	"github.com/tumi8/goscanner/scanner/results"
	"github.com/tumi8/goscanner/tls"
	"sort"
)

type ExtensionTask struct {
	dependencyGraphSH  []*extensionDependencyNode
	dependencyGraphEE  []*extensionDependencyNode
	dependencyGraphCR  []*extensionDependencyNode
	dependencyGraphHRR []*extensionDependencyNode
	dependencyGraphCT  []*extensionDependencyNode
}

type extensionDependencyNode struct {
	extension uint16
	outgoing  []*extensionDependencyNode
}

func (c *ExtensionTask) SetCHValues(*tls.ClientHelloPreset, *results.ServerModel, float64, bool, int) {
}

func (c *ExtensionTask) Done(*results.ServerModel) bool {
	return false
}

func (c *ExtensionTask) ResolveError(*results.ServerModel) (learnedSomething bool) { return }

func (c *ExtensionTask) MergeData(state tls.ConnectionState, model *results.ServerModel, preset *tls.ClientHelloPreset, err error) (errorCouldBeMe bool, learnedSomething bool) {
	learnedSomething = learnedSomething || extractExtensionDependencies(state.ServerExtensions, &c.dependencyGraphSH)
	learnedSomething = learnedSomething || extractExtensionDependencies(state.ServerEncryptedExtensions, &c.dependencyGraphEE)
	learnedSomething = learnedSomething || extractExtensionDependencies(state.ServerCertRequestExtensions, &c.dependencyGraphCR)
	learnedSomething = learnedSomething || extractExtensionDependencies(state.HelloRetryRequestExtensions, &c.dependencyGraphHRR)
	learnedSomething = learnedSomething || extractExtensionDependencies(state.CertificateExtensions, &c.dependencyGraphCT)
	return
}

func getCreateNode(extension tls.Extension, graph *[]*extensionDependencyNode) (node *extensionDependencyNode, learnedSomething bool) {
	for i := range *graph {
		if (*graph)[i].extension == extension.Extension {
			node = (*graph)[i]
		}
	}
	if node == nil {
		*graph = append(*graph, &extensionDependencyNode{extension: extension.Extension})
		node = (*graph)[len(*graph)-1]
		learnedSomething = true
	}
	return
}

func extractExtensionDependencies(extension []tls.Extension, order *[]*extensionDependencyNode) (learnedSomething bool) {
	if len(extension) > 1 {
		for i := range extension {
			if i > 0 {
				a, isNew := getCreateNode(extension[i-1], order)
				learnedSomething = learnedSomething || isNew
				b, isNew := getCreateNode(extension[i], order)
				learnedSomething = learnedSomething || isNew
				newEdge := true
				for j := range a.outgoing {
					if a.outgoing[j] == b {
						newEdge = false
					}
				}
				if newEdge {
					a.outgoing = append(a.outgoing, b)
					learnedSomething = true
				}
			}
		}
	} else if len(extension) == 1 {
		_, learnedSomething = getCreateNode(extension[0], order)
	}
	return
}

func (c *ExtensionTask) PostProcess(model *results.ServerModel) {
	model.ExtensionsConsistent = true
	model.ExtensionsConsistent = model.ExtensionsConsistent && applyToModelSingle(&c.dependencyGraphSH, &model.ExtensionOrderSH)
	model.ExtensionsConsistent = model.ExtensionsConsistent && applyToModelSingle(&c.dependencyGraphEE, &model.ExtensionOrderEE)
	model.ExtensionsConsistent = model.ExtensionsConsistent && applyToModelSingle(&c.dependencyGraphCR, &model.ExtensionOrderCR)
	model.ExtensionsConsistent = model.ExtensionsConsistent && applyToModelSingle(&c.dependencyGraphHRR, &model.ExtensionOrderHRR)
	model.ExtensionsConsistent = model.ExtensionsConsistent && applyToModelSingle(&c.dependencyGraphCT, &model.ExtensionOrderCT)
}

/*
*
1. Check if graph is a Tree => No Tree means inconsistent extensions
2. Remove Transitive Edges
3. Generate Paths from every node with no predecessor
*/
func applyToModelSingle(graph *[]*extensionDependencyNode, result *[][]uint16) (consistent bool) {

	if !graphIsTree(graph) {
		var r []uint16
		for _, node := range *graph {
			r = append(r, node.extension)
		}
		sort.Slice(r, func(i, j int) bool {
			return r[i] < r[j]
		})
		*result = append(*result, r)
		return false
	}

	var middleNodes []*extensionDependencyNode
	for _, n := range *graph {
		removeTransitiveEdgesRecursive(n, n)

		for _, o := range n.outgoing {
			present := false
			for _, m := range middleNodes {
				if o == m {
					present = true
				}
			}
			if !present {
				middleNodes = append(middleNodes, o)
			}
		}
	}

	var startingNodes []*extensionDependencyNode
	for _, n := range *graph {
		present := false
		for _, m := range middleNodes {
			if m == n {
				present = true
			}
		}
		if !present {
			startingNodes = append(startingNodes, n)
		}
	}

	var r [][]uint16
	for _, n := range startingNodes {
		r = append(r, sequentiateRecursive(n)...)
	}
	sort.Slice(r, func(i, j int) bool {
		l := misc.MinInt(len(r[i]), len(r[j]))
		for k := 0; k < l; k++ {
			if r[i][k] < r[j][k] {
				return true
			}
		}
		return len(r[i]) < len(r[j])
	})

	*result = r
	return true
}

func graphIsTree(graph *[]*extensionDependencyNode) bool {
	for _, n := range *graph {
		if !graphIsTreeRecursive(n, nil) {
			return false
		}
	}
	return true
}

func graphIsTreeRecursive(node *extensionDependencyNode, checkedNodes []*extensionDependencyNode) bool {
	for _, n := range checkedNodes {
		if node == n {
			return false
		}
	}
	checkedNodes = append(checkedNodes, node)
	for _, out := range node.outgoing {
		if !graphIsTreeRecursive(out, checkedNodes) {
			return false
		}
	}
	return true
}

func removeTransitiveEdgesRecursive(start, current *extensionDependencyNode) {
	if start != current {
		for _, out := range current.outgoing {
			for i, outStart := range start.outgoing {
				if out == outStart {
					start.outgoing = append(start.outgoing[:i], start.outgoing[i+1:]...)
					break
				}
			}
		}
	}
	for _, out := range current.outgoing {
		removeTransitiveEdgesRecursive(start, out)
	}
}

func sequentiateRecursive(start *extensionDependencyNode) (result [][]uint16) {
	for _, out := range start.outgoing {
		result = append(result, sequentiateRecursive(out)...)
	}
	if len(result) == 0 {
		result = append(result, []uint16{start.extension})
	} else {
		for i := range result {
			result[i] = append([]uint16{start.extension}, result[i]...)
		}
	}
	return
}
