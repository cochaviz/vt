package cli

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
)

const defaultZipPassword = "infected"

func newDownloadCmd() *cobra.Command {
	var outDir, outFile, password string
	var raw, force bool
	cmd := &cobra.Command{
		Use:   "download <hash>...",
		Short: "Download samples (password-protected zip by default)",
		Long: `Download samples by MD5, SHA-1 or SHA-256. Requires a premium API key.

By default VirusTotal packs the samples into a single password-protected zip
(password "infected", or zip_password from config / --password). Use --raw to
write each sample as-is to <dir>/<hash> instead.

Use "-" (or pipe into vt download) to read hashes from stdin.`,
		Example: `  vt download 44d88612fea8a8f36de82e1278abb02f
  vt download -o samples/ --raw <sha256> <sha256>
  vt lookup --known - < hashes.txt | vt download -O batch.zip`,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := expandArgs(args)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return fmt.Errorf("requires at least one hash")
			}
			for i, a := range args {
				if !isHash(a) {
					return fmt.Errorf("%q is not an MD5, SHA-1 or SHA-256 hash", a)
				}
				args[i] = strings.ToLower(a)
			}
			if outDir == "" {
				outDir = cfg.DownloadDir
			}
			if outDir == "" {
				outDir = "."
			}
			if err := os.MkdirAll(outDir, 0o755); err != nil {
				return err
			}
			c, err := client()
			if err != nil {
				return err
			}
			if raw {
				if outFile != "" {
					return fmt.Errorf("--output-file can't be combined with --raw")
				}
				return downloadRaw(c, args, outDir, force)
			}
			if password == "" {
				password = cfg.ZipPassword
			}
			if password == "" {
				password = defaultZipPassword
			}
			if outFile == "" {
				name := fmt.Sprintf("vt-%s.zip", time.Now().Format("20060102-150405"))
				if len(args) == 1 {
					name = args[0] + ".zip"
				}
				outFile = filepath.Join(outDir, name)
			}
			return downloadZip(c, args, outFile, password, force)
		},
	}
	f := cmd.Flags()
	f.StringVarP(&outDir, "output-dir", "o", "", "directory to write to (default download_dir from config, else .)")
	f.StringVarP(&outFile, "output-file", "O", "", "zip file path (default <hash>.zip or vt-<timestamp>.zip)")
	f.StringVarP(&password, "password", "p", "", "zip password (default zip_password from config, else \"infected\")")
	f.BoolVar(&raw, "raw", false, "write unpacked samples instead of a zip")
	f.BoolVarP(&force, "force", "f", false, "overwrite existing files")
	return cmd
}

type downloadResult struct {
	Hash  string `json:"hash"`
	Path  string `json:"path,omitempty"`
	Bytes int64  `json:"bytes,omitempty"`
	Error string `json:"error,omitempty"`
}

func downloadRaw(c *vt.Client, hashes []string, dir string, force bool) error {
	var results []downloadResult
	var failed int
	for _, h := range hashes {
		r := downloadResult{Hash: h, Path: filepath.Join(dir, h)}
		err := writeAtomic(r.Path, force, func(w io.Writer) error {
			p := newProgress(h[:min(12, len(h))], -1)
			defer p.Done()
			n, err := c.DownloadFile(h, p.writer(w))
			r.Bytes = n
			return err
		})
		if err != nil {
			failed++
			r.Error, r.Path = describeErr(err), ""
			fmt.Fprintf(os.Stderr, "%s: %s\n", h, r.Error)
		} else if !opts.json {
			fmt.Printf("%s  %s (%s)\n", h, r.Path, humanSize(r.Bytes))
		}
		results = append(results, r)
	}
	if opts.json {
		if err := printJSON(results); err != nil {
			return err
		}
	}
	if failed > 0 {
		return fmt.Errorf("%d of %d downloads failed", failed, len(hashes))
	}
	return nil
}

func downloadZip(c *vt.Client, hashes []string, path, password string, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
	}

	resp, err := c.PostData(vt.URL("intelligence/zip_files"), map[string]any{
		"password": password,
		"hashes":   hashes,
	})
	if err != nil {
		return err
	}
	zipObj := &vt.Object{}
	if err := zipObj.UnmarshalJSON(resp.Data); err != nil {
		return err
	}

	p := newProgress(filepath.Base(path), -1)
	start := time.Now()
	for {
		status := attrString(zipObj, "status")
		switch status {
		case "finished":
		case "timeout", "error-starting", "error-creating":
			p.Done()
			return fmt.Errorf("zip creation failed: %s", status)
		default:
			p.Status(fmt.Sprintf("VirusTotal is creating the zip (%s, %d%%, %s)",
				status, attrInt(zipObj, "progress"), fmtDuration(time.Since(start))))
			time.Sleep(pollInterval() / 3) // zips are usually quick; poll faster than analyses
			if zipObj, err = c.GetObject(vt.URL("intelligence/zip_files/%s", zipObj.ID())); err != nil {
				p.Done()
				return err
			}
			continue
		}
		break
	}
	p.Done()

	var dlURL string
	if _, err := c.GetData(vt.URL("intelligence/zip_files/%s/download_url", zipObj.ID()), &dlURL); err != nil {
		return err
	}

	var size int64
	err = writeAtomic(path, force, func(w io.Writer) error {
		hc := &http.Client{Timeout: requestTimeout()}
		res, err := hc.Get(dlURL)
		if err != nil {
			return err
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			return fmt.Errorf("zip download: HTTP %s", res.Status)
		}
		p := newProgress(filepath.Base(path), res.ContentLength)
		defer p.Done()
		size, err = io.Copy(p.writer(w), res.Body)
		return err
	})
	if err != nil {
		return err
	}

	ok, bad := attrInt(zipObj, "files_ok"), attrInt(zipObj, "files_error")
	if opts.json {
		return printJSON(map[string]any{
			"path": path, "bytes": size, "password": password,
			"files_ok": ok, "files_error": bad, "hashes": hashes,
		})
	}
	fmt.Printf("%s (%s, %d samples, password %q)\n", path, humanSize(size), ok, password)
	if bad > 0 {
		fmt.Fprintf(os.Stderr, "warning: %d of %d samples could not be included\n", bad, len(hashes))
	}
	return nil
}

// writeAtomic writes to a temp file next to path and renames it into place on
// success, so failed downloads never leave partial files behind.
func writeAtomic(path string, force bool, write func(io.Writer) error) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return fmt.Errorf("%s already exists (use --force to overwrite)", path)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".vt-download-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if err := write(tmp); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}
