package worker

import (
	"testing"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
)

// endpoint builds a discovered endpoint for the tests.
func endpoint(host string, port int, isWeb bool, url string) domain.TargetEndpoint {
	return domain.TargetEndpoint{
		Host:   host,
		Port:   port,
		IsWeb:  isWeb,
		URL:    url,
		Scheme: schemeOf(url),
	}
}

func schemeOf(url string) string {
	for i := 0; i+3 <= len(url); i++ {
		if url[i:i+3] == "://" {
			return url[:i]
		}
	}
	return ""
}

func allowAll(string) bool { return true }

func TestBuildTargetFilesSplitsWebAndNetworkPorts(t *testing.T) {
	endpoints := []domain.TargetEndpoint{
		endpoint("192.168.23.83", 135, false, ""),
		endpoint("192.168.23.83", 445, false, ""),
		endpoint("192.168.23.83", 3389, false, ""),
		endpoint("192.168.23.83", 1337, true, "http://192.168.23.83:1337"),
		endpoint("192.168.23.83", 47001, true, "http://192.168.23.83:47001"),
		endpoint("192.168.23.83", 5985, true, "http://192.168.23.83:5985"),
	}
	files := buildTargetFiles([]string{"192.168.23.83"}, endpoints, allowAll)

	wantWeb := []string{
		"192.168.23.83",
		"http://192.168.23.83:1337",
		"http://192.168.23.83:47001",
		"http://192.168.23.83:5985",
	}
	if len(files.Web) != len(wantWeb) {
		t.Fatalf("targets.txt has %d lines, want %d: %v", len(files.Web), len(wantWeb), files.Web)
	}
	for i := range wantWeb {
		if files.Web[i] != wantWeb[i] {
			t.Errorf("targets.txt line %d = %q, want %q", i, files.Web[i], wantWeb[i])
		}
	}
	if files.Original != 1 {
		t.Errorf("original lines = %d, want 1", files.Original)
	}

	wantNetwork := []string{"192.168.23.83:135", "192.168.23.83:3389", "192.168.23.83:445"}
	if len(files.Network) != len(wantNetwork) {
		t.Fatalf("network_targets.txt has %d lines, want %d: %v", len(files.Network), len(wantNetwork), files.Network)
	}
	for i := range wantNetwork {
		if files.Network[i] != wantNetwork[i] {
			t.Errorf("network_targets.txt line %d = %q, want %q", i, files.Network[i], wantNetwork[i])
		}
	}
}

// TestBuildTargetFilesNeverURLsUnconfirmedPorts checks that a port httpx did
// not confirm as a web service never shows up as a URL.
func TestBuildTargetFilesNeverURLsUnconfirmedPorts(t *testing.T) {
	endpoints := []domain.TargetEndpoint{
		endpoint("192.168.23.83", 445, false, ""),
		endpoint("192.168.23.83", 135, false, ""),
	}
	files := buildTargetFiles([]string{"192.168.23.83"}, endpoints, allowAll)

	for _, line := range files.Web {
		if line != "192.168.23.83" {
			t.Errorf("unexpected URL %q for a port httpx did not confirm", line)
		}
	}
	if len(files.Network) != 2 {
		t.Errorf("network_targets.txt has %d lines, want 2: %v", len(files.Network), files.Network)
	}
}

// TestBuildTargetFilesDropsOutOfScope checks that an endpoint outside the
// scope allowlist is dropped from both files.
func TestBuildTargetFilesDropsOutOfScope(t *testing.T) {
	endpoints := []domain.TargetEndpoint{
		endpoint("192.168.23.83", 445, false, ""),
		endpoint("10.1.2.3", 8080, true, "http://10.1.2.3:8080"),
		endpoint("10.1.2.3", 22, false, ""),
	}
	allowed := func(host string) bool { return host == "192.168.23.83" }
	files := buildTargetFiles([]string{"192.168.23.83"}, endpoints, allowed)

	for _, line := range files.Web {
		if line != "192.168.23.83" {
			t.Errorf("out of scope endpoint kept in targets.txt: %q", line)
		}
	}
	for _, line := range files.Network {
		if line != "192.168.23.83:445" {
			t.Errorf("out of scope endpoint kept in network_targets.txt: %q", line)
		}
	}
}

// TestBuildTargetFilesDeduplicatesAndSorts checks that the generated lines are
// stable: deduplicated case-insensitively, without trailing slashes and sorted.
func TestBuildTargetFilesDeduplicatesAndSorts(t *testing.T) {
	endpoints := []domain.TargetEndpoint{
		endpoint("192.168.23.83", 443, true, "https://192.168.23.83:443/"),
		endpoint("192.168.23.83", 443, true, "https://192.168.23.83:443"),
		endpoint("192.168.23.83", 80, true, "http://192.168.23.83:80"),
		endpoint("192.168.23.83", 22, false, ""),
		endpoint("192.168.23.83", 22, false, ""),
	}
	files := buildTargetFiles([]string{"192.168.23.83/", "192.168.23.83"}, endpoints, allowAll)

	want := []string{"192.168.23.83", "http://192.168.23.83:80", "https://192.168.23.83:443"}
	if len(files.Web) != len(want) {
		t.Fatalf("targets.txt has %d lines, want %d: %v", len(files.Web), len(want), files.Web)
	}
	for i := range want {
		if files.Web[i] != want[i] {
			t.Errorf("targets.txt line %d = %q, want %q", i, files.Web[i], want[i])
		}
	}
	if len(files.Network) != 1 {
		t.Errorf("network_targets.txt has %d lines, want 1: %v", len(files.Network), files.Network)
	}
}

// TestBuildTargetFilesWithoutDiscovery checks that a run without discovery
// only feeds the original target values to nuclei.
func TestBuildTargetFilesWithoutDiscovery(t *testing.T) {
	files := buildTargetFiles([]string{"192.168.23.83"}, nil, allowAll)
	if len(files.Web) != 1 || files.Web[0] != "192.168.23.83" {
		t.Errorf("targets.txt = %v, want [192.168.23.83]", files.Web)
	}
	if len(files.Network) != 0 {
		t.Errorf("network_targets.txt = %v, want empty", files.Network)
	}
}

// TestBuildTargetFilesBuildsURLFromScheme checks that a web endpoint without
// a URL but with a scheme still becomes a full URL.
func TestBuildTargetFilesBuildsURLFromScheme(t *testing.T) {
	ep := domain.TargetEndpoint{Host: "192.168.23.83", Port: 8080, IsWeb: true, Scheme: "http"}
	files := buildTargetFiles([]string{"192.168.23.83"}, []domain.TargetEndpoint{ep}, allowAll)
	if len(files.Web) != 2 || files.Web[1] != "http://192.168.23.83:8080" {
		t.Errorf("targets.txt = %v, want the original plus http://192.168.23.83:8080", files.Web)
	}
}
