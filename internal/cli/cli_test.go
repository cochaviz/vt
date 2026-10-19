package cli

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	vt "github.com/VirusTotal/vt-go"
)

const (
	knownSHA  = "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
	unknownMD = "00000000000000000000000000000000"
)

func TestResolve(t *testing.T) {
	cases := map[string]string{
		knownSHA:                           "files/" + knownSHA,
		"44D88612FEA8A8F36DE82E1278ABB02F": "files/44d88612fea8a8f36de82e1278abb02f",
		"https://example.com/":             "urls/aHR0cHM6Ly9leGFtcGxlLmNvbS8",
		"1.2.3.4":                          "ip_addresses/1.2.3.4",
		"2001:db8::1":                      "ip_addresses/2001:db8::1",
		"Evil.Example":                     "domains/evil.example",
	}
	for in, want := range cases {
		got, err := resolve(in)
		if err != nil || got.Path != want {
			t.Errorf("resolve(%q) = %q, %v; want %q", in, got.Path, err, want)
		}
	}
	for _, bad := range []string{"", "abc", "not a domain"} {
		if _, err := resolve(bad); err == nil {
			t.Errorf("resolve(%q) succeeded, want error", bad)
		}
	}
}

func fakeVT(t *testing.T) *httptest.Server {
	fileObj := map[string]any{"data": map[string]any{
		"id": knownSHA, "type": "file",
		"attributes": map[string]any{
			"md5": "44d88612fea8a8f36de82e1278abb02f", "meaningful_name": "eicar.com",
			"size": 68, "type_tag": "text", "type_description": "Text",
			"last_analysis_date":  1700000000,
			"last_analysis_stats": map[string]any{"malicious": 60, "suspicious": 1, "undetected": 5, "harmless": 0},
			"last_analysis_results": map[string]any{
				"EngineA": map[string]any{"category": "malicious", "result": "EICAR-Test-File"},
				"EngineB": map[string]any{"category": "undetected", "result": nil},
			},
			"popular_threat_classification": map[string]any{"suggested_threat_label": "virus.eicar/test"},
		},
	}}
	analysis := map[string]any{"data": map[string]any{"id": "an-1", "type": "analysis",
		"attributes": map[string]any{"status": "completed", "stats": map[string]any{"malicious": 3, "undetected": 7}}}}
	zipPolls := 0

	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Apikey") != "test-key" && !strings.HasPrefix(r.URL.Path, "/zipdata") {
			w.WriteHeader(401)
			return
		}
		writeJSON := func(v any) { w.Header().Set("Content-Type", "application/json"); json.NewEncoder(w).Encode(v) }
		notFound := func() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(404)
			json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": "NotFoundError", "message": "not found"}})
		}
		p := strings.TrimPrefix(r.URL.Path, "/api/v3/")
		switch {
		case p == "files/"+knownSHA:
			writeJSON(fileObj)
		case p == "files/"+knownSHA+"/download":
			io.WriteString(w, "X5O!P%@AP")
		case p == "files/"+knownSHA+"/analyse", p == "files", p == "urls":
			writeJSON(map[string]any{"data": map[string]any{"id": "an-1", "type": "analysis"}})
		case p == "analyses/an-1":
			writeJSON(analysis)
		case p == "intelligence/zip_files" && r.Method == "POST":
			writeJSON(map[string]any{"data": map[string]any{"id": "z1", "type": "zip_file", "attributes": map[string]any{"status": "starting"}}})
		case p == "intelligence/zip_files/z1":
			zipPolls++
			writeJSON(map[string]any{"data": map[string]any{"id": "z1", "type": "zip_file",
				"attributes": map[string]any{"status": "finished", "files_ok": 1, "files_error": 0}}})
		case p == "intelligence/zip_files/z1/download_url":
			writeJSON(map[string]any{"data": srv.URL + "/zipdata"})
		case r.URL.Path == "/zipdata":
			io.WriteString(w, "PK-fake-zip")
		default:
			notFound()
		}
	}))
	t.Cleanup(srv.Close)
	vt.SetHost(srv.URL)
	t.Setenv("VT_API_KEY", "test-key")
	t.Setenv("VT_CONFIG", filepath.Join(t.TempDir(), "vt.yaml"))
	return srv
}

// run executes the CLI with args and returns captured stdout.
func run(t *testing.T, args ...string) (string, error) {
	t.Helper()
	opts = globalOpts{}
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w
	cmd := newRootCmd()
	cmd.SetArgs(append([]string{"--no-progress"}, args...))
	err := cmd.Execute()
	w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	io.Copy(&buf, r)
	return buf.String(), err
}

func TestCommands(t *testing.T) {
	fakeVT(t)
	cfgFile := os.Getenv("VT_CONFIG")
	os.WriteFile(cfgFile, []byte("poll_interval: 10ms\n"), 0o600)

	out, err := run(t, "get", "-e", knownSHA)
	t.Log("\n" + out)
	if err != nil || !strings.Contains(out, "60/66") || !strings.Contains(out, "virus.eicar/test") ||
		!strings.Contains(out, "EICAR-Test-File") || strings.Contains(out, "EngineB") {
		t.Errorf("get: err=%v\n%s", err, out)
	}

	out, err = run(t, "--json", "get", knownSHA)
	var obj map[string]any
	if err != nil || json.Unmarshal([]byte(out), &obj) != nil || obj["id"] != knownSHA {
		t.Errorf("get --json: err=%v\n%s", err, out)
	}

	out, err = run(t, "lookup", knownSHA, unknownMD)
	t.Log("\n" + out)
	if err != nil || !strings.Contains(out, "known") || !strings.Contains(out, "unknown") {
		t.Errorf("lookup: err=%v\n%s", err, out)
	}
	out, _ = run(t, "lookup", "--unknown", knownSHA, unknownMD)
	if strings.TrimSpace(out) != unknownMD {
		t.Errorf("lookup --unknown: %q", out)
	}

	dir := t.TempDir()
	if _, err := run(t, "download", "--raw", "-o", dir, knownSHA); err != nil {
		t.Fatalf("download --raw: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, knownSHA)); string(b) != "X5O!P%@AP" {
		t.Errorf("raw download content = %q", b)
	}
	if _, err := run(t, "download", "--raw", "-o", dir, knownSHA); err == nil {
		t.Error("download should refuse to overwrite without --force")
	}
	if _, err := run(t, "download", "--raw", "-o", dir, unknownMD); err == nil {
		t.Error("download of unknown hash should fail")
	}
	if _, err := os.Stat(filepath.Join(dir, unknownMD)); err == nil {
		t.Error("failed download left a file behind")
	}

	if _, err := run(t, "download", "-o", dir, knownSHA); err != nil {
		t.Fatalf("download zip: %v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(dir, knownSHA+".zip")); string(b) != "PK-fake-zip" {
		t.Errorf("zip content = %q", b)
	}

	// upload: one known file (skipped) and one new file (uploaded, waited on).
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "new.bin"), []byte("brand new"), 0o644)
	os.MkdirAll(filepath.Join(src, "sub"), 0o755)
	os.WriteFile(filepath.Join(src, "sub", "eicar.com"), []byte("known content"), 0o644)
	out, err = run(t, "upload", "--wait", src)
	if err != nil || !strings.Contains(out, "analyzed") || !strings.Contains(out, "3/10") {
		t.Errorf("upload: err=%v\n%s", err, out)
	}

	out, err = run(t, "scan", "--wait", knownSHA, "https://example.com/")
	if err != nil || strings.Count(out, "completed") != 2 {
		t.Errorf("scan: err=%v\n%s", err, out)
	}
	if _, err := run(t, "scan", "evil.example"); err == nil {
		t.Error("scanning a domain should fail")
	}

	if _, err := run(t, "config", "set", "download_dir", "/tmp/x"); err != nil {
		t.Fatal(err)
	}
	if out, _ := run(t, "config", "get", "download_dir"); strings.TrimSpace(out) != "/tmp/x" {
		t.Errorf("config get = %q", out)
	}
}
