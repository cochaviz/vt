package cli

import (
	"fmt"
	"os"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
)

type scanResult struct {
	Query      string `json:"query"`
	AnalysisID string `json:"analysis_id,omitempty"`
	Status     string `json:"status"`
	Detections string `json:"detections,omitempty"`
	Error      string `json:"error,omitempty"`
}

func newScanCmd() *cobra.Command {
	var wait bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "scan <hash|url>...",
		Short: "Request a fresh analysis of known files or of URLs (new URLs are submitted)",
		Long: `Ask VirusTotal to reanalyse files it already has (by hash), or to scan URLs.
URLs VirusTotal has never seen are submitted. To analyse a new file, use
"vt upload". With --wait, vt polls until each analysis completes.`,
		Example: `  vt scan <sha256>
  vt scan --wait https://example.com/login`,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := expandArgs(args)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return fmt.Errorf("requires at least one hash or URL")
			}
			c, err := client()
			if err != nil {
				return err
			}
			tw := newTable(os.Stdout)
			if !opts.json {
				fmt.Fprintln(tw, "QUERY\tANALYSIS\tSTATUS\tDETECTIONS")
			}
			var results []scanResult
			var failed int
			for _, a := range args {
				r := scanOne(c, a, wait, timeout)
				if r.Error != "" {
					failed++
					fmt.Fprintf(os.Stderr, "%s: %s\n", a, r.Error)
				}
				results = append(results, r)
				if !opts.json {
					fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", a, dash(r.AnalysisID), r.Status, dash(r.Detections))
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
				return fmt.Errorf("%d of %d scans failed", failed, len(args))
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&wait, "wait", "w", false, "wait for each analysis to complete")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Minute, "give up waiting for an analysis after this long")
	return cmd
}

func scanOne(c *vt.Client, arg string, wait bool, timeout time.Duration) scanResult {
	r := scanResult{Query: arg, Status: "failed"}
	fail := func(err error) scanResult {
		r.Error = describeErr(err)
		return r
	}
	t, err := resolve(arg)
	if err != nil {
		return fail(err)
	}

	analysis := &vt.Object{}
	switch t.Kind {
	case "file":
		resp, err := c.Post(vt.URL("%s/analyse", t.Path), nil)
		if err != nil {
			return fail(err)
		}
		if err := analysis.UnmarshalJSON(resp.Data); err != nil {
			return fail(err)
		}
	case "url":
		if analysis, err = c.NewURLScanner().Scan(t.Arg); err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("only files (by hash) and URLs can be scanned, not %ss", t.Kind))
	}
	r.Status, r.AnalysisID = "queued", analysis.ID()

	if wait {
		done, err := waitAnalysis(c, analysis.ID(), arg, timeout)
		if err != nil {
			return fail(err)
		}
		r.Status = "completed"
		if s, ok := analysisStats(done, "stats"); ok {
			r.Detections = s.ratio()
		}
	}
	return r
}
