// Package telefonistka provides domain types and orchestration logic
// for safe, controlled GitOps promotion across environments and
// failure domains.
package telefonistka

import "k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"

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
// Kubernetes resource, ready for formatting.
type ResourcePair struct {
	Group     string
	Kind      string
	Namespace string
	Name      string
	Live      *unstructured.Unstructured // nil → new resource
	Target    *unstructured.Unstructured // nil → deleted resource
}

// ComponentDiff holds app metadata and the resource pairs produced
// by diffing live cluster state against target manifests.
type ComponentDiff struct {
	Name            string
	Namespace       string
	HealthStatus    string
	SyncStatus      string
	AutoSyncEnabled bool
	TargetRevision  string
	TempCreated     bool
	Pairs           []ResourcePair
}
