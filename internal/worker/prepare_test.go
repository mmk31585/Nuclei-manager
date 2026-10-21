package worker

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mmk31585/Nuclei-manager/internal/discovery"
	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/scanner/nuclei"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
)

type fakeScopeRepo struct{ entries []domain.ScopeEntry }

func (f *fakeScopeRepo) Create(context.Context, *domain.ScopeEntry) error { return nil }
func (f *fakeScopeRepo) List(context.Context) ([]domain.ScopeEntry, error) {
	return f.entries, nil
}
func (f *fakeScopeRepo) Delete(context.Context, uint) error { return nil }

type fakeEndpointRepo struct{ endpoints []domain.TargetEndpoint }

func (f *fakeEndpointRepo) Upsert(_ context.Context, eps []domain.TargetEndpoint) error {
	f.endpoints = append(f.endpoints, eps...)
	return nil
}
func (f *fakeEndpointRepo) ListByTarget(context.Context, uint) ([]domain.TargetEndpoint, error) {
	return f.endpoints, nil
}

type fakeDiscoverer struct{ endpoints []domain.Endpoint }

func (f *fakeDiscoverer) Discover(context.Context, []string, discovery.Options) ([]domain.Endpoint, error) {
	return f.endpoints, nil
}

// newTestWorker builds a worker whose discovery always returns the given
// endpoints and whose scope allows the test host only.
func newTestWorker(t *testing.T, dir string, scanNetworkPorts bool, eps []domain.Endpoint) (*Worker, *domain.Run) {
	t.Helper()
	snap := domain.ConfigSnapshot{
		Task:    domain.Task{ID: 1, Name: "t", TargetID: 1, ProfileID: 1, ScanNetworkPorts: scanNetworkPorts},
		Target:  domain.Target{ID: 1, Name: "t", Hosts: []string{"192.168.23.83"}},
		Profile: domain.Profile{ID: 1, Name: "p"},
	}
	raw, err := snap.Encode()
	if err != nil {
		t.Fatalf("encode snapshot: %v", err)
	}
	w := &Worker{
		cfg: Config{
			DataDir:         dir,
			Nuclei:          nuclei.Info{Path: "/usr/local/bin/nuclei", Version: "v3.11.1"},
			Discovery:       &fakeDiscoverer{endpoints: eps},
			TargetEndpoints: &fakeEndpointRepo{},
		},
		scope: scope.NewService(&fakeScopeRepo{entries: []domain.ScopeEntry{
			{ID: 1, Kind: domain.ScopeIP, Value: "192.168.23.83"},
		}}),
	}
	return w, &domain.Run{ID: 7, TaskID: 1, ConfigSnapshot: raw}
}

func TestPrepareWritesBothTargetFiles(t *testing.T) {
	dir := t.TempDir()
	eps := []domain.Endpoint{
		{Host: "192.168.23.83", Port: 445, IsWeb: false, Source: "naabu"},
		{Host: "192.168.23.83", Port: 1337, IsWeb: true, URL: "http://192.168.23.83:1337", Source: "httpx"},
	}
	w, run := newTestWorker(t, dir, true, eps)
	prep, err := w.prepare(context.Background(), run)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}

	web := readFile(t, filepath.Join(dir, "runs", "7", "targets.txt"))
	want := "192.168.23.83\nhttp://192.168.23.83:1337\n"
	if web != want {
		t.Errorf("targets.txt = %q, want %q", web, want)
	}
	network := readFile(t, filepath.Join(dir, "runs", "7", "network_targets.txt"))
	if network != "192.168.23.83:445\n" {
		t.Errorf("network_targets.txt = %q, want %q", network, "192.168.23.83:445\n")
	}
	if len(prep.files.Web) != 2 || len(prep.files.Network) != 1 {
		t.Errorf("prepared files = %d web, %d network; want 2 and 1", len(prep.files.Web), len(prep.files.Network))
	}
	if prep.files.Original != 1 {
		t.Errorf("original lines = %d, want 1", prep.files.Original)
	}
}

func TestPrepareWithoutNetworkScanHasNoSecondPass(t *testing.T) {
	dir := t.TempDir()
	eps := []domain.Endpoint{
		{Host: "192.168.23.83", Port: 445, IsWeb: false, Source: "naabu"},
	}
	w, run := newTestWorker(t, dir, false, eps)
	prep, err := w.prepare(context.Background(), run)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if len(prep.networkArgs) != 0 {
		t.Errorf("scan_network_ports=false must not build a second pass, got %v", prep.networkArgs)
	}
	if prep.scanNetworkPorts {
		t.Errorf("scanNetworkPorts = true, want false")
	}
}

func TestPrepareNetworkPassUsesNetworkProtocols(t *testing.T) {
	dir := t.TempDir()
	eps := []domain.Endpoint{
		{Host: "192.168.23.83", Port: 445, IsWeb: false, Source: "naabu"},
	}
	w, run := newTestWorker(t, dir, true, eps)
	prep, err := w.prepare(context.Background(), run)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	if len(prep.networkArgs) == 0 {
		t.Fatalf("scan_network_ports=true must build a second pass")
	}
	joined := strings.Join(prep.networkArgs, " ")
	if !strings.Contains(joined, "-pt tcp,javascript") {
		t.Errorf("network pass args = %v, want -pt tcp,javascript", prep.networkArgs)
	}
	if !strings.Contains(joined, filepath.Join(dir, "runs", "7", "network_targets.txt")) {
		t.Errorf("network pass args = %v, want the network targets file", prep.networkArgs)
	}
	// The web pass must not use the network protocol filter.
	webJoined := strings.Join(prep.webArgs, " ")
	if strings.Contains(webJoined, "-pt ") {
		t.Errorf("web pass args = %v, want no protocol filter", prep.webArgs)
	}
}

func TestPrepareMinimalCommand(t *testing.T) {
	dir := t.TempDir()
	w, run := newTestWorker(t, dir, false, nil)
	prep, err := w.prepare(context.Background(), run)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	joined := strings.Join(prep.webArgs, " ")
	for _, f := range []string{"-severity", "-rate-limit", "-concurrency", "-bulk-size", "-max-host-error"} {
		if strings.Contains(joined, f+" ") || strings.HasSuffix(joined, f) {
			t.Errorf("unexpected flag %q in %v", f, prep.webArgs)
		}
	}
	for _, want := range []string{"-list", "-jsonl"} {
		if !strings.Contains(joined, want) {
			t.Errorf("args %v missing %q", prep.webArgs, want)
		}
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}
