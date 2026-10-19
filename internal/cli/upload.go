package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
)

type uploadResult struct {
	File       string `json:"file"`
	SHA256     string `json:"sha256,omitempty"`
	Status     string `json:"status"` // known, uploaded, analyzed, failed
	AnalysisID string `json:"analysis_id,omitempty"`
	Detections string `json:"detections,omitempty"`
	Error      string `json:"error,omitempty"`
}

func newUploadCmd() *cobra.Command {
	var force, wait bool
	var password string
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "upload <path>...",
		Short: "Upload sample files (directories are walked recursively)",
		Long: `Upload files to VirusTotal for analysis. Directories are walked recursively.

Each file is hashed locally first; files VirusTotal already knows are skipped
unless --force is given (use "vt scan <hash>" to reanalyse a known file).
With --wait, vt polls until each analysis completes and prints the verdict.`,
		Example: `  vt upload sample.exe
  vt upload --wait ./samples/
  vt upload --password infected archive.zip`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := collectFiles(args)
			if err != nil {
				return err
			}
			if len(files) == 0 {
				return fmt.Errorf("no files found")
			}
			c, err := client()
			if err != nil {
				return err
			}
			params := map[string]string{}
			if password != "" {
				params["password"] = password
			}

			tw := newTable(os.Stdout)
			if !opts.json {
				fmt.Fprintln(tw, "FILE\tSHA256\tSTATUS\tDETECTIONS")
			}
			var results []uploadResult
			var failed int
			for _, f := range files {
				r := uploadOne(c, f, params, force, wait, timeout)
				if r.Error != "" {
					failed++
					fmt.Fprintf(os.Stderr, "%s: %s\n", f, r.Error)
				}
				results = append(results, r)
				if !opts.json {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", f, dash(r.SHA256), r.Status, dash(r.Detections))
				}
			}
			if opts.json {
				if err := printJSON(results); err != nil {
					return err
				}
			} else {
				tw.Flush()
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d uploads failed", failed, len(files))
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.BoolVarP(&force, "force", "f", false, "upload even if VirusTotal already knows the file")
	f.BoolVarP(&wait, "wait", "w", false, "wait for each analysis to complete")
	f.DurationVar(&timeout, "timeout", 20*time.Minute, "give up waiting for an analysis after this long")
	f.StringVar(&password, "password", "", "password VirusTotal should use to open uploaded archives")
	return cmd
}

func uploadOne(c *vt.Client, path string, params map[string]string, force, wait bool, timeout time.Duration) uploadResult {
	r := uploadResult{File: path, Status: "failed"}
	fail := func(err error) uploadResult {
		r.Error = describeErr(err)
		return r
	}

	f, err := os.Open(path)
	if err != nil {
		return fail(err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return fail(err)
	}
	r.SHA256 = hex.EncodeToString(h.Sum(nil))

	if !force {
		o, err := c.GetObject(vt.URL("files/%s", r.SHA256))
		if err == nil {
			r.Status = "known"
			if s, ok := analysisStats(o, "last_analysis_stats"); ok {
				r.Detections = s.ratio()
			}
			return r
		}
		if !isNotFound(err) {
			return fail(err)
		}
	}

	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return fail(err)
	}
	st, err := f.Stat()
	if err != nil {
		return fail(err)
	}
	p := newProgress(filepath.Base(path), st.Size())
	ch, waitProgress := p.uploadChannel()
	analysis, err := c.NewFileScanner().ScanWithParameters(f, filepath.Base(path), ch, params)
	waitProgress()
	p.Done()
	if err != nil {
		return fail(err)
	}
	r.Status, r.AnalysisID = "uploaded", analysis.ID()

	if wait {
		done, err := waitAnalysis(c, analysis.ID(), filepath.Base(path), timeout)
		if err != nil {
			return fail(err)
		}
		r.Status = "analyzed"
		if s, ok := analysisStats(done, "stats"); ok {
			r.Detections = s.ratio()
		}
	}
	return r
}

// collectFiles expands directories into the regular files beneath them.
func collectFiles(paths []string) ([]string, error) {
	var out []string
	for _, p := range paths {
		err := filepath.WalkDir(p, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.Type().IsRegular() {
				out = append(out, path)
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}
