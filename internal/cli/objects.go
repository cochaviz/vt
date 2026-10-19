package cli

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"regexp"
	"strings"

	vt "github.com/VirusTotal/vt-go"
)

// target is a CLI argument resolved to a VirusTotal object.
type target struct {
	Arg  string // as typed by the user
	Kind string // file, url, domain, ip
	Path string // API path, e.g. files/<hash>
}

var hashRe = regexp.MustCompile(`^(?i:[0-9a-f]{32}|[0-9a-f]{40}|[0-9a-f]{64})$`)

func isHash(s string) bool { return hashRe.MatchString(s) }

// resolve guesses the object type of an argument: a hash (MD5/SHA-1/SHA-256),
// an http(s) URL, an IP address, or otherwise a domain.
func resolve(arg string) (target, error) {
	s := strings.TrimSpace(arg)
	switch {
	case s == "":
		return target{}, fmt.Errorf("empty argument")
	case isHash(s):
		return target{arg, "file", "files/" + strings.ToLower(s)}, nil
	case strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://"):
		return target{arg, "url", "urls/" + urlID(s)}, nil
	case net.ParseIP(s) != nil:
		return target{arg, "ip", "ip_addresses/" + s}, nil
	case strings.Contains(s, ".") && !strings.ContainsAny(s, "/ "):
		return target{arg, "domain", "domains/" + strings.ToLower(s)}, nil
	}
	return target{}, fmt.Errorf("%q is not a hash, URL, IP address or domain", arg)
}

// urlID is the VirusTotal identifier of a URL: unpadded URL-safe base64.
func urlID(u string) string {
	return base64.RawURLEncoding.EncodeToString([]byte(u))
}

func fetch(c *vt.Client, t target) (*vt.Object, error) {
	return c.GetObject(vt.URL("%s", t.Path))
}

// expandArgs replaces a "-" argument (or no arguments, when stdin is piped)
// with whitespace-separated tokens read from stdin. Lines starting with # are skipped.
func expandArgs(args []string) ([]string, error) {
	if len(args) == 0 && !stdinIsTTY() {
		args = []string{"-"}
	}
	var out []string
	for _, a := range args {
		if a != "-" {
			out = append(out, a)
			continue
		}
		toks, err := readTokens(os.Stdin)
		if err != nil {
			return nil, err
		}
		out = append(out, toks...)
	}
	return out, nil
}

func readTokens(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		out = append(out, strings.Fields(line)...)
	}
	return out, sc.Err()
}

func stdinIsTTY() bool {
	fi, err := os.Stdin.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
