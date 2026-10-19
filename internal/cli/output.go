package cli

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	vt "github.com/VirusTotal/vt-go"
)

// printJSON writes v as indented JSON to stdout.
func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// printObjectsJSON prints a single object, or an array when there are several.
func printObjectsJSON(objs []*vt.Object) error {
	if len(objs) == 1 {
		return printJSON(objs[0])
	}
	if objs == nil {
		objs = []*vt.Object{}
	}
	return printJSON(objs)
}

func newTable(w io.Writer) *tabwriter.Writer {
	return tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
}

// --- attribute helpers: missing or mistyped attributes yield zero values ---

func attrString(o *vt.Object, name string) string {
	s, _ := o.GetString(name)
	return s
}

func attrInt(o *vt.Object, name string) int64 {
	n, _ := o.GetInt64(name)
	return n
}

func attrTime(o *vt.Object, name string) string {
	t, err := o.GetTime(name)
	if err != nil || t.IsZero() || t.Unix() == 0 {
		return ""
	}
	return t.UTC().Format("2006-01-02 15:04 UTC")
}

func attrStrings(o *vt.Object, name string) []string {
	s, _ := o.GetStringSlice(name)
	return s
}

func attrMap(o *vt.Object, name string) map[string]any {
	v, err := o.Get(name)
	if err != nil {
		return nil
	}
	m, _ := v.(map[string]any)
	return m
}

func toInt(v any) int64 {
	switch n := v.(type) {
	case json.Number:
		i, _ := n.Int64()
		return i
	case float64:
		return int64(n)
	case int64:
		return n
	case int:
		return int64(n)
	}
	return 0
}

// stats summarizes last_analysis_stats.
type stats struct {
	Malicious, Suspicious, Undetected, Harmless, Total int64
}

func analysisStats(o *vt.Object, attr string) (stats, bool) {
	m := attrMap(o, attr)
	if m == nil {
		return stats{}, false
	}
	s := stats{
		Malicious:  toInt(m["malicious"]),
		Suspicious: toInt(m["suspicious"]),
		Undetected: toInt(m["undetected"]),
		Harmless:   toInt(m["harmless"]),
	}
	// Total counts engines that produced a verdict, as the VT UI does.
	s.Total = s.Malicious + s.Suspicious + s.Undetected + s.Harmless
	return s, true
}

func (s stats) ratio() string {
	return fmt.Sprintf("%d/%d", s.Malicious, s.Total)
}

func (s stats) String() string {
	return fmt.Sprintf("%s (malicious %d, suspicious %d, undetected %d, harmless %d)",
		s.ratio(), s.Malicious, s.Suspicious, s.Undetected, s.Harmless)
}

// engineResult is one AV engine verdict from last_analysis_results.
type engineResult struct {
	Engine, Category, Result string
}

// flaggedEngines returns engines whose category is malicious or suspicious (or all, if all is set).
func flaggedEngines(o *vt.Object, attr string, all bool) []engineResult {
	var out []engineResult
	for engine, v := range attrMap(o, attr) {
		r, _ := v.(map[string]any)
		cat, _ := r["category"].(string)
		res, _ := r["result"].(string)
		if !all && cat != "malicious" && cat != "suspicious" {
			continue
		}
		out = append(out, engineResult{engine, cat, res})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Category != out[j].Category {
			return out[i].Category < out[j].Category
		}
		return strings.ToLower(out[i].Engine) < strings.ToLower(out[j].Engine)
	})
	return out
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func joinLimit(items []string, max int) string {
	if len(items) <= max {
		return strings.Join(items, ", ")
	}
	return strings.Join(items[:max], ", ") + fmt.Sprintf(" (+%d more)", len(items)-max)
}

func fmtDuration(d time.Duration) string {
	return d.Round(time.Second).String()
}
