package cli

import (
	"fmt"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print client build information",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			info := map[string]string{
				"version": version,
				"commit":  commit,
				"date":    date,
				"go":      runtime.Version(),
				"os/arch": runtime.GOOS + "/" + runtime.GOARCH,
			}
			if bi, ok := debug.ReadBuildInfo(); ok {
				for _, d := range bi.Deps {
					if d.Path == "github.com/VirusTotal/vt-go" {
						info["vt-go"] = d.Version
					}
				}
			}
			if opts.json {
				return printJSON(info)
			}
			for _, k := range []string{"version", "commit", "date", "go", "os/arch", "vt-go"} {
				if v, ok := info[k]; ok {
					fmt.Printf("%-8s %s\n", k+":", v)
				}
			}
			return nil
		},
	}
}
