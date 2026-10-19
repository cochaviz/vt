package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type lookupResult struct {
	Query      string `json:"query"`
	Known      bool   `json:"known"`
	ID         string `json:"id,omitempty"`
	Type       string `json:"type,omitempty"`
	Detections string `json:"detections,omitempty"`
	Malicious  int64  `json:"malicious"`
	Name       string `json:"name,omitempty"`
	Error      string `json:"error,omitempty"`
}

func newLookupCmd() *cobra.Command {
	var unknownOnly, knownOnly bool
	cmd := &cobra.Command{
		Use:   "lookup <hash|url|domain|ip>...",
		Short: "Check which hashes (or URLs, domains, IPs) are known, one line each",
		Long: `Check whether each argument is known to VirusTotal and print a one-line
summary per argument. Reads from stdin with "-" or when piped, so it works
well with sha256sum output or a file of hashes:

  cut -d' ' -f1 hashes.txt | vt lookup
  vt lookup --unknown - < hashes.txt   # print only hashes VT has never seen`,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := expandArgs(args)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return fmt.Errorf("requires at least one argument")
			}
			c, err := client()
			if err != nil {
				return err
			}

			var results []lookupResult
			tw := newTable(os.Stdout)
			if !opts.json && !unknownOnly && !knownOnly {
				fmt.Fprintln(tw, "QUERY\tSTATUS\tDETECTIONS\tTYPE\tNAME")
			}
			var errs int
			for _, a := range args {
				r := lookupResult{Query: a}
				t, err := resolve(a)
				if err == nil {
					o, ferr := fetch(c, t)
					switch {
					case ferr == nil:
						r.Known, r.ID, r.Type = true, o.ID(), o.Type()
						if s, ok := analysisStats(o, "last_analysis_stats"); ok {
							r.Detections, r.Malicious = s.ratio(), s.Malicious
						}
						if t.Kind == "file" {
							r.Type = attrString(o, "type_tag")
							r.Name = attrString(o, "meaningful_name")
						}
					case isNotFound(ferr):
					default:
						err = ferr
					}
				}
				if err != nil {
					errs++
					r.Error = describeErr(err)
					fmt.Fprintf(os.Stderr, "%s: %s\n", a, r.Error)
				}
				results = append(results, r)

				if opts.json {
					continue
				}
				switch {
				case r.Error != "":
				case unknownOnly:
					if !r.Known {
						fmt.Fprintln(tw, a)
					}
				case knownOnly:
					if r.Known {
						fmt.Fprintln(tw, a)
					}
				case r.Known:
					fmt.Fprintf(tw, "%s\tknown\t%s\t%s\t%s\n", a, dash(r.Detections), dash(r.Type), truncate(r.Name, 40))
				default:
					fmt.Fprintf(tw, "%s\tunknown\t-\t-\t\n", a)
				}
			}
			tw.Flush()
			if opts.json {
				if err := printJSON(results); err != nil {
					return err
				}
			}
			if errs > 0 {
				return fmt.Errorf("%d of %d lookups failed", errs, len(args))
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&unknownOnly, "unknown", false, "only print arguments VirusTotal doesn't know")
	cmd.Flags().BoolVar(&knownOnly, "known", false, "only print arguments VirusTotal knows")
	cmd.MarkFlagsMutuallyExclusive("unknown", "known")
	return cmd
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
