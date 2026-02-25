// Package diff formats Kubernetes resource diffs for human consumption.
//
// It is intentionally free of ArgoCD client dependencies.
package diff

import (
	"bytes"
	"fmt"

	telefonistka "github.com/commercetools/telefonistka"
	"github.com/gonvenience/ytbx"
	"github.com/homeport/dyff/pkg/dyff"
	yaml3 "gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

// FormatPairDiff formats a [telefonistka.ResourcePair] into a
// [telefonistka.Element]. When keepDiffData is false a redacted
// placeholder is returned. The caller should skip elements where
// Diff is empty — this happens when dyff considers the two
// representations identical.
func FormatPairDiff(pair telefonistka.ResourcePair, keepDiffData bool) (telefonistka.Element, error) {
	el := telefonistka.Element{
		ObjectName:      pair.Name,
		ObjectKind:      pair.Kind,
		ObjectNamespace: pair.Namespace,
	}
	if !keepDiffData {
		el.Diff = telefonistka.RedactedDiff
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

