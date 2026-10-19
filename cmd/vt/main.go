package main

import (
	"os"

	"github.com/cochaviz/vt/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
