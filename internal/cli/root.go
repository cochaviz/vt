// Package cli implements the vt command tree.
package cli

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"

	vt "github.com/VirusTotal/vt-go"
	"github.com/spf13/cobra"

	"github.com/cochaviz/vt/internal/config"
)

// Build information, set with -ldflags "-X github.com/cochaviz/vt/internal/cli.version=...".
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

type globalOpts struct {
	json       bool
	noProgress bool
	apiKey     string
}

var (
	opts globalOpts
	cfg  *config.Config
)

func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:           "vt",
		Short:         "Command-line client for VirusTotal",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			c, err := config.Load()
			if err != nil {
				return err
			}
			cfg = c
			return nil
		},
	}
	root.SetVersionTemplate("{{.Version}}\n")

	pf := root.PersistentFlags()
	pf.BoolVar(&opts.json, "json", false, "print raw JSON responses")
	pf.BoolVar(&opts.noProgress, "no-progress", false, "don't show transfer progress")
	pf.StringVar(&opts.apiKey, "api-key", "", "VirusTotal API key (overrides config and VT_API_KEY)")

	root.AddCommand(
		newConfigCmd(),
		newDownloadCmd(),
		newGetCmd(),
		newLookupCmd(),
		newRelatedCmd(),
		newScanCmd(),
		newAnalysisCmd(),
		newSearchCmd(),
		newUploadCmd(),
		newVersionCmd(),
	)
	return root
}

// Execute runs the CLI and returns the process exit code.
func Execute() int {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", describeErr(err))
		return 1
	}
	return 0
}

// client builds a vt client from flag > env > config.
func client() (*vt.Client, error) {
	key := opts.apiKey
	if key == "" {
		key = os.Getenv("VT_API_KEY")
	}
	if key == "" {
		key = cfg.APIKey
	}
	if key == "" {
		return nil, errors.New("no API key: run `vt config set api_key <key>`, set VT_API_KEY, or pass --api-key")
	}
	c := vt.NewClient(key, vt.WithHTTPClient(&http.Client{Timeout: requestTimeout()}))
	c.Agent = "vt-cli/" + version
	return c, nil
}

func requestTimeout() time.Duration {
	return durationSetting(cfg.RequestTimeout, 0)
}

func pollInterval() time.Duration {
	return durationSetting(cfg.PollInterval, 15*time.Second)
}

func durationSetting(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		fmt.Fprintf(os.Stderr, "warning: invalid duration %q in config, using %s\n", s, def)
		return def
	}
	return d
}

// describeErr turns common API errors into friendlier messages.
func describeErr(err error) string {
	var apiErr vt.Error
	if errors.As(err, &apiErr) {
		switch apiErr.Code {
		case "NotFoundError":
			return "not found on VirusTotal: " + apiErr.Message
		case "WrongCredentialsError", "AuthenticationRequiredError":
			return "invalid or missing API key (" + apiErr.Message + ")"
		case "ForbiddenError":
			return "forbidden; this usually needs a premium API key (" + apiErr.Message + ")"
		case "QuotaExceededError":
			return "API quota exceeded (" + apiErr.Message + ")"
		}
		return apiErr.Code + ": " + apiErr.Message
	}
	return err.Error()
}

func isNotFound(err error) bool {
	var apiErr vt.Error
	return errors.As(err, &apiErr) && apiErr.Code == "NotFoundError"
}
