// ngfwebpfdrill writes first-party artifacts for the OL9 eBPF attach drill.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/detailtech/oss-ngfw/internal/ebpfdrill"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: ngfwebpfdrill <write-probes|manifest>")
	}
	switch args[0] {
	case "write-probes":
		fs := flag.NewFlagSet("write-probes", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var buildDir string
		fs.StringVar(&buildDir, "build-dir", "", "required directory for generated XDP/tc probe source")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectArgs("write-probes", fs.Args()); err != nil {
			return err
		}
		paths, err := ebpfdrill.WriteProbeSources(buildDir)
		if err != nil {
			return fmt.Errorf("write probes: %w", err)
		}
		if _, err := fmt.Fprintf(stdout, "xdp_probe_source=%s\n", paths.XDPSource); err != nil {
			return fmt.Errorf("write XDP probe source output: %w", err)
		}
		if _, err := fmt.Fprintf(stdout, "tc_probe_source=%s\n", paths.TCSource); err != nil {
			return fmt.Errorf("write tc probe source output: %w", err)
		}
		return nil
	case "manifest":
		fs := flag.NewFlagSet("manifest", flag.ContinueOnError)
		fs.SetOutput(stderr)
		var buildDir, iface, output string
		fs.StringVar(&buildDir, "build-dir", "", "required directory containing generated source and compiled objects")
		fs.StringVar(&iface, "iface", "", "required disposable interface used for the attach drill")
		fs.StringVar(&output, "output", "", "required manifest output path")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if err := rejectArgs("manifest", fs.Args()); err != nil {
			return err
		}
		if err := ebpfdrill.WriteManifest(output, ebpfdrill.DefaultManifestOptions(buildDir, iface)); err != nil {
			return fmt.Errorf("write manifest: %w", err)
		}
		if _, err := fmt.Fprintf(stdout, "manifest=%s\n", output); err != nil {
			return fmt.Errorf("write manifest output: %w", err)
		}
		return nil
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func rejectArgs(command string, args []string) error {
	if len(args) == 0 {
		return nil
	}
	return fmt.Errorf("%s received unexpected argument %q", command, args[0])
}
