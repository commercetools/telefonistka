// Package diff formats Kubernetes resource diffs for human consumption.
//
// It is intentionally free of ArgoCD client dependencies. The
// pairing of live vs target resources (which involves ArgoCD's
// StateDiff algorithm) is handled by the argocd package, which
// produces [ResourcePair] values that this package formats.
package diff

import (
	"bytes"
	"fmt"

	"github.com/gonvenience/ytbx"
	"github.com/homeport/dyff/pkg/dyff"
	yaml3 "gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// RedactedDiff is the placeholder shown when diff content is
// suppressed by per-component configuration.
const RedactedDiff = "✂️ ✂️  Redacted ✂️ ✂️ \nUnset component-level configuration key `disableArgoCDDiff` to see diff content."

// Element represents a single diffed Kubernetes object.
type Element struct {
	ObjectName      string
	ObjectKind      string
	ObjectNamespace string
	Diff            string
}

// ResourcePair holds the live and desired state of a single
// Kubernetes resource, ready for formatting. Produced by
// [argocd.PairResources], consumed by [FormatPairDiff].
type ResourcePair struct {
	Group     string
	Kind      string
	Namespace string
	Name      string
	Live      *unstructured.Unstructured // nil → new resource
	Target    *unstructured.Unstructured // nil → deleted resource
}

// FormatPairDiff formats a resource pair into an [Element].
// When keepDiffData is false a redacted placeholder is returned.
// The caller should skip elements where Diff is empty — this
// happens when dyff considers the two representations identical.
func FormatPairDiff(pair ResourcePair, keepDiffData bool) (Element, error) {
	el := Element{
		ObjectName:      pair.Name,
		ObjectKind:      pair.Kind,
		ObjectNamespace: pair.Namespace,
	}
	if !keepDiffData {
		el.Diff = RedactedDiff
		return el, nil
	}
	d, err := FormatDiff(pair.Live, pair.Target)
	if err != nil {
		return el, fmt.Errorf("formatting diff for %s/%s: %w", pair.Kind, pair.Name, err)
	}
	el.Diff = d
	return el, nil
}

// FormatDiff produces a human-readable diff between two Kubernetes
// resources in a format compatible with GitHub markdown diff
// highlighting. Either argument may be nil (nil live = creation,
// nil target = deletion). Returns an empty string when dyff finds
// the two representations semantically identical.
func FormatDiff(live, target *unstructured.Unstructured) (string, error) {
	if live == nil {
		live = &unstructured.Unstructured{}
	}
	if target == nil {
		target = &unstructured.Unstructured{}
	}

	// Use target metadata for the header; for deletions the target
	// is empty so the header fields will be blank (the Element
	// carries the correct metadata separately).
	kind := target.GetKind()
	name := target.GetName()
	apiVersion := target.GetAPIVersion()

	var liveNode yaml3.Node
	var targetNode yaml3.Node

	marshaledLive, _ := live.MarshalJSON()
	marshaledTarget, _ := target.MarshalJSON()

	_ = yaml3.Unmarshal(marshaledLive, &liveNode)
	_ = yaml3.Unmarshal(marshaledTarget, &targetNode)

	liveIf := ytbx.InputFile{
		Location:  "live",
		Documents: []*yaml3.Node{&liveNode},
	}
	targetIf := ytbx.InputFile{
		Location:  "target",
		Documents: []*yaml3.Node{&targetNode},
	}

	dReport, err := dyff.CompareInputFiles(liveIf, targetIf, dyff.KubernetesEntityDetection(true))
	if err != nil {
		return "", fmt.Errorf("generating Dyff report: %w", err)
	}

	reportWriter := &dyff.DiffSyntaxReport{
		PathPrefix:            "@@",
		RootDescriptionPrefix: "#",
		ChangeTypePrefix:      "!",
		HumanReport: dyff.HumanReport{
			Report:                dReport,
			Indent:                0,
			DoNotInspectCerts:     true,
			NoTableStyle:          true,
			OmitHeader:            false,
			UseGoPatchPaths:       false,
			MinorChangeThreshold:  0.1,
			MultilineContextLines: 4,
			PrefixMultiline:       true,
		},
	}

	out := new(bytes.Buffer)
	if err := reportWriter.WriteReport(out); err != nil {
		return "", fmt.Errorf("formatting Dyff report: %w", err)
	}

	// dyff may find zero differences when ArgoCD's StateDiff
	// reports Modified. Return empty so the caller can skip.
	if len(dReport.Diffs) == 0 {
		return "", nil
	}

	header := "apiVersion: " + apiVersion + "\nkind: " + kind + "\nmetadata:\n  name: " + name + "\n"
	return header + out.String(), nil
}

// IsHookOrIgnored returns true if the object carries an ArgoCD
// sync hook annotation or an explicit compare-options=ignore
// annotation.
func IsHookOrIgnored(obj *unstructured.Unstructured) bool {
	annotations := obj.GetAnnotations()
	if _, ok := annotations["argocd.argoproj.io/hook"]; ok {
		return true
	}
	return annotations["argocd.argoproj.io/compare-options"] == "ignore"
}
