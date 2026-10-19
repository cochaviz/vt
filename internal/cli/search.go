package cli

import (
	"fmt"
	"os"
	"strings"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"
)

func newSearchCmd() *cobra.Command {
	var limit int
	var idsOnly bool
	cmd := &cobra.Command{
		Use:   "search <query>",
		Short: "Search with VirusTotal Intelligence (premium), newest first",
		Long: `Run a VirusTotal Intelligence search. All arguments are joined into one query.
See https://docs.virustotal.com/docs/search-modifiers for the query syntax.`,
		Example: `  vt search 'type:peexe p:20+ fs:7d-'
  vt search --ids 'tag:cve-2024-3400' | vt download --raw -o samples/`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			c, err := client()
			if err != nil {
				return err
			}
			it, err := c.Search(strings.Join(args, " "), vt.IteratorLimit(limit))
			if err != nil {
				return err
			}
			return printIterator(it, idsOnly)
		},
	}
	cmd.Flags().IntVarP(&limit, "limit", "n", 20, "maximum number of results")
	cmd.Flags().BoolVar(&idsOnly, "ids", false, "print only object IDs (for piping)")
	return cmd
}

func newRelatedCmd() *cobra.Command {
	var limit int
	var idsOnly bool
	cmd := &cobra.Command{
		Use:   "related <hash|url|domain|ip> <relationship>",
		Short: "List objects related to a file, URL, domain or IP",
		Long: `List objects related to another object through a relationship, e.g.
contacted_domains, contacted_ips, dropped_files, execution_parents,
bundled_files, similar_files (files); communicating_files, resolutions,
subdomains, downloaded_files (domains/IPs); and many more. Some
relationships require a premium API key.

See https://docs.virustotal.com/reference/files#relationships`,
		Example: `  vt related <sha256> contacted_domains
  vt related evil.example communicating_files --ids | vt lookup`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			t, err := resolve(args[0])
			if err != nil {
				return err
			}
			c, err := client()
			if err != nil {
				return err
			}
			it, err := c.Iterator(vt.URL("%s/%s", t.Path, args[1]), vt.IteratorLimit(limit))
			if err != nil {
				return err
			}
			return printIterator(it, idsOnly)
		},
	}
	cmd.Flags().IntVarP(&limit, "limit", "n", 40, "maximum number of results")
	cmd.Flags().BoolVar(&idsOnly, "ids", false, "print only object IDs (for piping)")
	return cmd
}

// printIterator prints objects as a table, IDs, or a JSON array.
func printIterator(it *vt.Iterator, idsOnly bool) error {
	defer it.Close()
	var objs []*vt.Object
	tw := newTable(os.Stdout)
	if !opts.json && !idsOnly {
		fmt.Fprintln(tw, "ID\tTYPE\tDETECTIONS\tINFO")
	}
	for it.Next() {
		o := it.Get()
		switch {
		case opts.json:
			objs = append(objs, o)
		case idsOnly:
			fmt.Println(objectArg(o))
		default:
			det := "-"
			if s, ok := analysisStats(o, "last_analysis_stats"); ok {
				det = s.ratio()
			}
			typ := o.Type()
			if tag := attrString(o, "type_tag"); tag != "" {
				typ = tag
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", o.ID(), typ, det, truncate(objectInfo(o), 60))
		}
	}
	if err := it.Error(); err != nil {
		tw.Flush()
		return err
	}
	if opts.json {
		if objs == nil {
			objs = []*vt.Object{}
		}
		return printJSON(objs)
	}
	return tw.Flush()
}

// objectArg returns something vt get/lookup can take back: URLs are printed as
// the URL itself, since their IDs aren't accepted as arguments.
func objectArg(o *vt.Object) string {
	if o.Type() == "url" {
		if u := attrString(o, "url"); u != "" {
			return u
		}
	}
	return o.ID()
}

func objectInfo(o *vt.Object) string {
	switch o.Type() {
	case "file":
		info := attrString(o, "meaningful_name")
		if n := attrInt(o, "size"); n > 0 {
			info = strings.TrimSpace(info + " " + humanSize(n))
		}
		return info
	case "url":
		return attrString(o, "url")
	case "domain":
		return attrString(o, "registrar")
	case "ip_address":
		return strings.TrimSpace(attrString(o, "country") + " " + attrString(o, "as_owner"))
	case "resolution":
		return attrString(o, "host_name") + " -> " + attrString(o, "ip_address") + " " + attrTime(o, "date")
	}
	return ""
}
