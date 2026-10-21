package nuclei

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

type Info struct {
	Path             string
	Version          string // "unknown" when it cannot be parsed
	TemplatesVersion string // best effort, may be empty
}

// Flags the service passes to nuclei. Probe fails fast if the installed binary lacks any of them.
var RequiredFlags = []string{
	"list", "jsonl", "no-color", "disable-update-check", "stats", "stats-interval",
	"rate-limit", "concurrency", "bulk-size", "timeout", "retries", "max-host-error",
	"no-interactsh", "exclude-hosts", "templates", "template-id", "tags", "exclude-tags",
	"severity", "pt",
}

var (
	reEngine = regexp.MustCompile(`(?i)engine version:\s*(v?\d+\.\d+\.\d+\S*)`)
	reAnyVer = regexp.MustCompile(`v\d+\.\d+\.\d+\S*`)
	reTpl    = regexp.MustCompile(`(?i)templates version:\s*(\S+)`)
)

// MissingFlags returns the required flags that do not appear in the help text.
func MissingFlags(help string, required []string) []string {
	var missing []string
	for _, f := range required {
		re := regexp.MustCompile(`(?m)(?:^|[\s,])-` + regexp.QuoteMeta(f) + `(?:[\s,]|$)`)
		if !re.MatchString(help) {
			missing = append(missing, "-"+f)
		}
	}
	return missing
}

func parseVersion(out string) (version, templates string) {
	version = "unknown"
	if m := reEngine.FindStringSubmatch(out); m != nil {
		version = m[1]
	} else if m := reAnyVer.FindString(out); m != "" {
		version = m
	}
	if m := reTpl.FindStringSubmatch(out); m != nil {
		templates = m[1]
	}
	return version, templates
}

func Probe(ctx context.Context, bin string) (Info, error) {
	path, err := exec.LookPath(bin)
	if err != nil {
		return Info{}, fmt.Errorf("nuclei binary %q not found: %w", bin, err)
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	verOut, err := exec.CommandContext(ctx, path, "-version", "-disable-update-check").CombinedOutput()
	if err != nil && len(verOut) == 0 {
		return Info{}, fmt.Errorf("run %s -version: %w", path, err)
	}
	helpOut, err := exec.CommandContext(ctx, path, "-h").CombinedOutput()
	if err != nil && len(helpOut) == 0 {
		return Info{}, fmt.Errorf("run %s -h: %w", path, err)
	}
	if missing := MissingFlags(string(helpOut), RequiredFlags); len(missing) > 0 {
		return Info{}, fmt.Errorf("installed nuclei is too old or changed its flags, missing: %s", strings.Join(missing, " "))
	}
	v, t := parseVersion(string(verOut))
	return Info{Path: path, Version: v, TemplatesVersion: t}, nil
}
