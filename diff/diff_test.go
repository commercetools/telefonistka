package diff

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"text/template"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func readFileString(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func readManifest(t *testing.T, path string) *unstructured.Unstructured {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	obj := &unstructured.Unstructured{}
	if err := json.Unmarshal(b, &obj.Object); err != nil {
		t.Fatalf("unmarshal %s: %v", path, err)
	}
	return obj
}

func readLiveTarget(t *testing.T) (live, target *unstructured.Unstructured, expected string) {
	t.Helper()
	live = readManifest(t, "testdata/"+t.Name()+".live")
	target = readManifest(t, "testdata/"+t.Name()+".target")
	expected = readFileString(t, "testdata/"+t.Name()+".want")
	return live, target, expected
}

func TestFormatDiff(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
	}{
		{"1"},
		{"identical"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			live, target, want := readLiveTarget(t)
			got, err := FormatDiff(live, target)
			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if got != want {
				t.Errorf("got \n%q\n, want \n%q\n", got, want)
			}
		})
	}

	t.Run("no panic on nil inputs", func(t *testing.T) {
		defer func() {
			if err := recover(); err != nil {
				t.Errorf("got panic: %v", err)
			}
		}()
		FormatDiff(nil, nil) //nolint:errcheck // only interested in panic
	})

	t.Run("nil live produces diff", func(t *testing.T) {
		t.Parallel()
		target := &unstructured.Unstructured{}
		target.SetAPIVersion("apps/v1")
		target.SetKind("Deployment")
		target.SetName("nginx")
		target.SetNamespace("default")
		_ = unstructured.SetNestedField(target.Object, int64(3), "spec", "replicas")

		got, err := FormatDiff(nil, target)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got == "" {
			t.Fatal("expected non-empty diff for new resource, got empty string")
		}
		if !strings.Contains(got, "Deployment") {
			t.Errorf("expected diff to mention resource kind, got:\n%s", got)
		}
	})
}

func TestFormatDiffDeletion(t *testing.T) {
	t.Parallel()
	live := &unstructured.Unstructured{}
	live.SetAPIVersion("v1")
	live.SetKind("ConfigMap")
	live.SetName("my-config")
	live.SetNamespace("default")
	_ = unstructured.SetNestedStringMap(live.Object, map[string]string{"key": "value"}, "data")

	got, err := FormatDiff(live, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got == "" {
		t.Fatal("expected non-empty diff for deleted resource, got empty string")
	}
	if !strings.Contains(got, "my-config") || !strings.Contains(got, "value") {
		t.Errorf("expected diff to contain resource content, got:\n%s", got)
	}
}

func TestFormatPairDiffRedacted(t *testing.T) {
	t.Parallel()
	pair := ResourcePair{
		Kind:      "Deployment",
		Name:      "nginx",
		Namespace: "default",
	}
	el, err := FormatPairDiff(pair, false)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if el.Diff != RedactedDiff {
		t.Errorf("expected redacted diff, got: %q", el.Diff)
	}
	if el.ObjectName != "nginx" {
		t.Errorf("ObjectName = %q, want %q", el.ObjectName, "nginx")
	}
	if el.ObjectKind != "Deployment" {
		t.Errorf("ObjectKind = %q, want %q", el.ObjectKind, "Deployment")
	}
}

func TestRenderDiff(t *testing.T) {
	t.Parallel()
	live := readManifest(t, "testdata/TestRenderDiff.live")
	target := readManifest(t, "testdata/TestRenderDiff.target")
	want := readFileString(t, "testdata/TestRenderDiff.md")
	data, err := FormatDiff(live, target)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// backticks are tricky https://github.com/golang/go/issues/24475
	r := strings.NewReplacer("¬", "`")
	tmpl := r.Replace("¬¬¬diff\n{{.}}¬¬¬\n")

	rendered := renderTemplate(t, tmpl, data)

	if got, want := rendered.String(), want; got != want {
		t.Errorf("got \n%q\n, want \n%q\n", got, want)
	}
	t.Logf("got: \n%s\n", rendered.String())
}

func TestIsHookOrIgnored(t *testing.T) {
	t.Parallel()
	tests := map[string]struct {
		annotations map[string]string
		want        bool
	}{
		"hook annotation": {
			annotations: map[string]string{"argocd.argoproj.io/hook": "PreSync"},
			want:        true,
		},
		"ignore annotation": {
			annotations: map[string]string{"argocd.argoproj.io/compare-options": "ignore"},
			want:        true,
		},
		"no relevant annotations": {
			annotations: map[string]string{"other": "value"},
			want:        false,
		},
		"nil annotations": {
			annotations: nil,
			want:        false,
		},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			obj := &unstructured.Unstructured{}
			obj.SetAnnotations(tc.annotations)
			if got := IsHookOrIgnored(obj); got != tc.want {
				t.Errorf("IsHookOrIgnored() = %v, want %v", got, tc.want)
			}
		})
	}
}

func renderTemplate(t *testing.T, tpl string, data any) *bytes.Buffer {
	t.Helper()
	buf := bytes.NewBuffer(nil)
	tmpl := template.New("")
	tmpl = template.Must(tmpl.Parse(tpl))
	if err := tmpl.Execute(buf, data); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	return buf
}
