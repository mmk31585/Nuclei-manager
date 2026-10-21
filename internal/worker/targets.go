package worker

import (
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/mmk31585/Nuclei-manager/internal/domain"
	"github.com/mmk31585/Nuclei-manager/internal/scope"
)

// targetFiles is the split of the discovered endpoints into the two nuclei
// input files of a run.
type targetFiles struct {
	// Web is the main pass input: the original target values plus one URL per
	// endpoint httpx confirmed as a web service.
	Web []string
	// Network is the optional second pass input: one host:port per open port
	// that is not a web service.
	Network []string
	// Original counts how many Web lines are original target values.
	Original int
}

// buildTargetFiles splits the discovered endpoints into the two nuclei input files.
//
// The main pass gets the original target values exactly as entered plus a full
// URL for every endpoint httpx confirmed as a web service. A port that httpx
// did not confirm never becomes a URL: it ends up in the network list, where
// the network templates pick it up, or nowhere at all.
//
// Both lists are deduplicated case-insensitively, stripped of trailing slashes
// and sorted, so the generated files are stable between runs. Everything that
// is not covered by the scope allowlist is dropped from both files.
func buildTargetFiles(originals []string, endpoints []domain.TargetEndpoint, allowed func(host string) bool) targetFiles {
	var out targetFiles
	webSeen := make(map[string]bool)
	netSeen := make(map[string]bool)

	addWeb := func(line string) {
		line = trimTargetLine(line)
		key := strings.ToLower(line)
		if line == "" || webSeen[key] {
			return
		}
		webSeen[key] = true
		out.Web = append(out.Web, line)
	}
	addNetwork := func(line string) {
		line = trimTargetLine(line)
		key := strings.ToLower(line)
		if line == "" || netSeen[key] {
			return
		}
		netSeen[key] = true
		out.Network = append(out.Network, line)
	}

	for _, h := range originals {
		h = strings.TrimSpace(h)
		if h == "" || !hostAllowed(allowed, h) {
			continue
		}
		addWeb(h)
		out.Original++
	}

	for _, ep := range endpoints {
		if ep.Port <= 0 {
			continue
		}
		if ep.IsWeb {
			if u := endpointURL(ep); u != "" && hostAllowed(allowed, u) {
				addWeb(u)
				continue
			}
			// httpx confirmed the port but did not give a usable URL: fall
			// through and treat the port as a non-web service.
		}
		host := strings.TrimSpace(ep.Host)
		if host == "" || !hostAllowed(allowed, host) {
			continue
		}
		addNetwork(fmt.Sprintf("%s:%d", host, ep.Port))
	}

	sort.Strings(out.Web)
	sort.Strings(out.Network)
	return out
}

// endpointURL returns the full URL of a web endpoint, or an empty string when
// the endpoint carries no usable scheme.
func endpointURL(ep domain.TargetEndpoint) string {
	if u := trimTargetLine(ep.URL); u != "" {
		return u
	}
	scheme := strings.TrimSpace(strings.ToLower(ep.Scheme))
	if scheme == "" || ep.Host == "" {
		return ""
	}
	return scheme + "://" + net.JoinHostPort(ep.Host, strconv.Itoa(ep.Port))
}

// hostAllowed applies the scope allowlist to the host part of a target line.
func hostAllowed(allowed func(host string) bool, line string) bool {
	if allowed == nil {
		return true
	}
	host, err := scope.ExtractHost(line)
	if err != nil {
		return false
	}
	return allowed(host)
}

// trimTargetLine removes the surrounding blanks and the trailing slashes of a
// target line. The scheme separator of a bare "http://" is kept intact.
func trimTargetLine(s string) string {
	s = strings.TrimSpace(s)
	for strings.HasSuffix(s, "/") {
		next := strings.TrimSuffix(s, "/")
		if next == "" || strings.HasSuffix(next, ":") {
			return s
		}
		s = next
	}
	return s
}
