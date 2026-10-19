package cli

import (
	"fmt"
	"os"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
)

func newAnalysisCmd() *cobra.Command {
	var wait, engines bool
	var timeout time.Duration
	cmd := &cobra.Command{
		Use:   "analysis <analysis-id>...",
		Short: "Show the status and verdicts of an analysis (from upload or scan)",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client()
			if err != nil {
				return err
			}
			var objs []*vt.Object
			for i, id := range args {
				var o *vt.Object
				if wait {
					o, err = waitAnalysis(c, id, id, timeout)
				} else {
					o, err = c.GetObject(vt.URL("analyses/%s", id))
				}
				if err != nil {
					return err
				}
				objs = append(objs, o)
				if !opts.json {
					if i > 0 {
						fmt.Println()
					}
					printAnalysis(o, engines)
				}
			}
			if opts.json {
				return printObjectsJSON(objs)
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&wait, "wait", "w", false, "wait for the analysis to complete")
	cmd.Flags().DurationVar(&timeout, "timeout", 20*time.Minute, "give up waiting after this long")
	cmd.Flags().BoolVarP(&engines, "engines", "e", false, "list engines that flagged the object")
	return cmd
}

func printAnalysis(o *vt.Object, engines bool) {
	tw := newTable(os.Stdout)
	fmt.Fprintf(tw, "Analysis\t%s\n", o.ID())
	fmt.Fprintf(tw, "Status\t%s\n", attrString(o, "status"))
	if d := attrTime(o, "date"); d != "" {
		fmt.Fprintf(tw, "Date\t%s\n", d)
	}
	if s, ok := analysisStats(o, "stats"); ok && attrString(o, "status") == "completed" {
		fmt.Fprintf(tw, "Detections\t%s\n", s)
	}
	tw.Flush()
	if engines {
		tw := newTable(os.Stdout)
		fmt.Println()
		fmt.Fprintln(tw, "ENGINE\tCATEGORY\tRESULT")
		for _, r := range flaggedEngines(o, "results", false) {
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Engine, r.Category, dash(r.Result))
		}
		tw.Flush()
	}
}

// waitAnalysis polls an analysis until it completes or the timeout passes.
func waitAnalysis(c *vt.Client, id, label string, timeout time.Duration) (*vt.Object, error) {
	p := newProgress(label, -1)
	defer p.Done()
	start := time.Now()
	for {
		o, err := c.GetObject(vt.URL("analyses/%s", id))
		if err != nil {
			return nil, err
		}
		status := attrString(o, "status")
		if status == "completed" {
			return o, nil
		}
		if timeout > 0 && time.Since(start) > timeout {
			return o, fmt.Errorf("analysis %s still %q after %s", id, status, fmtDuration(timeout))
		}
		p.Status(fmt.Sprintf("analysis %s (%s)", status, fmtDuration(time.Since(start))))
		time.Sleep(pollInterval())
	}
}
