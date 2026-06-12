// ngfwctl is the OpenNGFW command-line client.
//
// M0 scope: report its own version and query a running controld over
// gRPC. Policy commands (`ngfwctl policy ...`, `commit`, `rollback`,
// `show`) arrive in M1.
package main

import (
	"os"

	"github.com/detailtech/oss-ngfw/internal/cli"
)

func main() {
	if err := cli.NewRootCommand().Execute(); err != nil {
		os.Exit(1)
	}
}
