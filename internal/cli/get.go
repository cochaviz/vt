package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
)

func newGetCmd() *cobra.Command {
	var engines, allEngines bool
	var attrs []string
	cmd := &cobra.Command{
		Use:   "get <hash|url|domain|ip>...",
		Short: "Show a report for files, URLs, domains or IPs (--engines for per-engine verdicts)",
		Long: `Show a VirusTotal report for each argument. The object type is detected
automatically: MD5/SHA-1/SHA-256 hashes are files, http(s):// arguments are
URLs, IP addresses are IPs, anything else with a dot is a domain.

Use "-" (or pipe into vt get) to read arguments from stdin.`,
		Example: `  vt get 44d88612fea8a8f36de82e1278abb02f
  vt get https://example.com/ evil.example 1.2.3.4
  vt get --engines <sha256>
  vt get --attr pe_info.imphash --attr type_tag <sha256>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := expandArgs(args)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				return fmt.Errorf("requires at least one hash, URL, domain or IP")
			}
			c, err := client()
			if err != nil {
				return err
			}
			var objs []*vt.Object
			var failed int
			for i, a := range args {
				t, err := resolve(a)
				if err == nil {
					var o *vt.Object
					if o, err = fetch(c, t); err == nil {
						objs = append(objs, o)
						if !opts.json {
							if i > 0 {
								fmt.Println()
							}
							switch {
							case len(attrs) > 0:
								printAttrs(os.Stdout, o, attrs)
							default:
								printReport(os.Stdout, o, engines || allEngines, allEngines)
							}
						}
						continue
					}
				}
				failed++
				fmt.Fprintf(os.Stderr, "%s: %s\n", a, describeErr(err))
			}
			if opts.json {
				if err := printObjectsJSON(objs); err != nil {
					return err
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d lookups failed", failed, len(args))
			}
			return nil
		},
	}
	cmd.Flags().BoolVarP(&engines, "engines", "e", false, "list engines that flagged the object")
	cmd.Flags().BoolVar(&allEngines, "all-engines", false, "list every engine's verdict")
	cmd.Flags().StringSliceVarP(&attrs, "attr", "a", nil, "print only these attributes (dotted paths, repeatable)")
	return cmd
}

func printAttrs(w io.Writer, o *vt.Object, attrs []string) {
	tw := newTable(w)
	for _, a := range attrs {
		v, err := o.Get(a)
		if err != nil || v == nil {
			fmt.Fprintf(tw, "%s\t-\n", a)
			continue
		}
		fmt.Fprintf(tw, "%s\t%v\n", a, v)
	}
	tw.Flush()
}

func printReport(w io.Writer, o *vt.Object, engines, allEngines bool) {
	tw := newTable(w)
	row := func(k, v string) {
		if v != "" {
			fmt.Fprintf(tw, "%s\t%s\n", k, v)
		}
	}

	switch o.Type() {
	case "file":
		row("SHA256", o.ID())
		row("SHA1", attrString(o, "sha1"))
		row("MD5", attrString(o, "md5"))
		row("Name", attrString(o, "meaningful_name"))
		if names := attrStrings(o, "names"); len(names) > 1 {
			row("Other names", joinLimit(names, 5))
		}
		row("Type", fileType(o))
		if n := attrInt(o, "size"); n > 0 {
			row("Size", fmt.Sprintf("%s (%d bytes)", humanSize(n), n))
		}
		row("Threat", attrString(o, "popular_threat_classification.suggested_threat_label"))
		row("First seen", attrTime(o, "first_submission_date"))
		row("Last analysis", attrTime(o, "last_analysis_date"))
		if n := attrInt(o, "times_submitted"); n > 0 {
			row("Submissions", fmt.Sprint(n))
		}
	case "url":
		row("URL", attrString(o, "url"))
		if final := attrString(o, "last_final_url"); final != attrString(o, "url") {
			row("Final URL", final)
		}
		row("Title", attrString(o, "title"))
		row("ID", o.ID())
		row("First seen", attrTime(o, "first_submission_date"))
		row("Last analysis", attrTime(o, "last_analysis_date"))
	case "domain":
		row("Domain", o.ID())
		row("Registrar", attrString(o, "registrar"))
		row("Created", attrTime(o, "creation_date"))
		row("Last analysis", attrTime(o, "last_analysis_date"))
	case "ip_address":
		row("IP", o.ID())
		row("Country", attrString(o, "country"))
		if asn := attrInt(o, "asn"); asn > 0 {
			row("ASN", fmt.Sprintf("AS%d %s", asn, attrString(o, "as_owner")))
		}
		row("Network", attrString(o, "network"))
		row("Last analysis", attrTime(o, "last_analysis_date"))
	default:
		row("ID", o.ID())
		row("Type", o.Type())
	}

	if s, ok := analysisStats(o, "last_analysis_stats"); ok {
		row("Detections", s.String())
	}
	if _, err := o.Get("reputation"); err == nil {
		row("Reputation", fmt.Sprint(attrInt(o, "reputation")))
	}
	row("Categories", categories(o))
	if tags := attrStrings(o, "tags"); len(tags) > 0 {
		row("Tags", joinLimit(tags, 15))
	}
	row("Link", guiLink(o))
	tw.Flush()

	if engines {
		results := flaggedEngines(o, "last_analysis_results", allEngines)
		fmt.Fprintln(w)
		if len(results) == 0 {
			fmt.Fprintln(w, "No engines flagged this object.")
			return
		}
		tw := newTable(w)
		fmt.Fprintln(tw, "ENGINE\tCATEGORY\tRESULT")
		for _, r := range results {
			res := r.Result
			if res == "" {
				res = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\n", r.Engine, r.Category, res)
		}
		tw.Flush()
	}
}

func fileType(o *vt.Object) string {
	desc := attrString(o, "type_description")
	tag := attrString(o, "type_tag")
	switch {
	case desc != "" && tag != "":
		return fmt.Sprintf("%s (%s)", desc, tag)
	case desc != "":
		return desc
	}
	return tag
}

// categories flattens the {vendor: category} map into unique values.
func categories(o *vt.Object) string {
	seen := map[string]bool{}
	var out []string
	for _, v := range attrMap(o, "categories") {
		s, _ := v.(string)
		if s != "" && !seen[strings.ToLower(s)] {
			seen[strings.ToLower(s)] = true
			out = append(out, s)
		}
	}
	return joinLimit(out, 6)
}

func guiLink(o *vt.Object) string {
	base := "https://www.virustotal.com/gui/"
	switch o.Type() {
	case "file":
		return base + "file/" + o.ID()
	case "url":
		return base + "url/" + o.ID()
	case "domain":
		return base + "domain/" + o.ID()
	case "ip_address":
		return base + "ip-address/" + o.ID()
	}
	return ""
}
