package cli

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/cochaviz/vt/internal/config"
)

func newConfigCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage client settings (" + config.Path() + ")",
	}

	var keyHelp strings.Builder
	for _, k := range config.Keys() {
		fmt.Fprintf(&keyHelp, "  %-16s %s\n", k.Name, k.Help)
	}

	show := &cobra.Command{
		Use:   "show",
		Short: "Print all settings (secrets masked)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			vals := map[string]string{}
			tw := newTable(os.Stdout)
			for _, k := range config.Keys() {
				v, _ := cfg.Get(k.Name)
				if k.Secret {
					v = mask(v)
				}
				vals[k.Name] = v
				fmt.Fprintf(tw, "%s\t%s\n", k.Name, dash(v))
			}
			if opts.json {
				return printJSON(vals)
			}
			return tw.Flush()
		},
	}

	get := &cobra.Command{
		Use:   "get <key>",
		Short: "Print one setting",
		Long:  "Print one setting. Keys:\n" + keyHelp.String(),
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			v, err := cfg.Get(args[0])
			if err != nil {
				return err
			}
			fmt.Println(v)
			return nil
		},
	}

	set := &cobra.Command{
		Use:   "set <key> [value]",
		Short: "Change a setting (prompts for the value if omitted)",
		Long: "Change a setting. If the value is omitted it is read from stdin, which keeps\n" +
			"API keys out of shell history. Keys:\n" + keyHelp.String(),
		Example: "  vt config set api_key\n  vt config set download_dir ~/samples",
		Args:    cobra.RangeArgs(1, 2),
		RunE: func(cmd *cobra.Command, args []string) error {
			var value string
			if len(args) == 2 {
				value = args[1]
			} else {
				if stdinIsTTY() {
					fmt.Fprintf(os.Stderr, "%s: ", args[0])
				}
				line, err := bufio.NewReader(os.Stdin).ReadString('\n')
				if err != nil && line == "" {
					return fmt.Errorf("no value given")
				}
				value = strings.TrimSpace(line)
			}
			if err := cfg.Set(args[0], value); err != nil {
				return err
			}
			if err := cfg.Save(); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "saved %s to %s\n", args[0], config.Path())
			return nil
		},
	}

	unset := &cobra.Command{
		Use:   "unset <key>",
		Short: "Clear a setting",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := cfg.Set(args[0], ""); err != nil {
				return err
			}
			return cfg.Save()
		},
	}

	path := &cobra.Command{
		Use:   "path",
		Short: "Print the config file location",
		Args:  cobra.NoArgs,
		Run:   func(cmd *cobra.Command, args []string) { fmt.Println(config.Path()) },
	}

	cmd.AddCommand(show, get, set, unset, path)
	return cmd
}

func mask(s string) string {
	if len(s) <= 8 {
		return strings.Repeat("*", len(s))
	}
	return s[:4] + strings.Repeat("*", len(s)-8) + s[len(s)-4:]
}
