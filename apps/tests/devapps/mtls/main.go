// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

// Command mtls is a set of runnable demos for the msal-go mTLS PR stack. Each subcommand isolates one
// capability and prints clearly labelled output suitable for a live presentation.
//
// Subcommands:
//
//	mtls-pop         acquire an mTLS proof-of-possession token (PR #632)
//	bearer-over-mtls acquire a Bearer token that still travels over the mTLS transport (PR #643)
//	cache-isolation  prove PoP and Bearer tokens do not collide in the cache (PR #632 + #643)
//	signer           authenticate with a crypto.Signer whose key is never exported (PR #647/#649)
//	fic              explain and (with config) run the two-leg FIC over mTLS PoP flow (PR #633)
//
// Run `mtls <subcommand> -h` for the flags a subcommand accepts. The signer subcommand and the
// explanatory path of fic run fully offline; the rest require the SN/I certificate and network access.
package main

import (
	"fmt"
	"os"
)

// subcommand describes one demo.
type subcommand struct {
	name string
	desc string
	run  func(args []string) error
}

func subcommands() []subcommand {
	return []subcommand{
		{"mtls-pop", "Acquire an mTLS proof-of-possession token (PR #632)", runMtlsPoP},
		{"bearer-over-mtls", "Acquire a Bearer token over the mTLS transport (PR #643)", runBearerOverMtls},
		{"cache-isolation", "Prove PoP and Bearer tokens do not collide in the cache (PR #632 + #643)", runCacheIsolation},
		{"signer", "Authenticate with a non-exportable crypto.Signer (PR #647/#649)", runSigner},
		{"fic", "Two-leg federated identity credential over mTLS PoP (PR #633)", runFIC},
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "mtls — demos for the msal-go mTLS PR stack")
	fmt.Fprintln(os.Stderr, "\nUsage: mtls <subcommand> [flags]")
	fmt.Fprintln(os.Stderr, "\nSubcommands:")
	for _, c := range subcommands() {
		fmt.Fprintf(os.Stderr, "  %-16s %s\n", c.name, c.desc)
	}
	fmt.Fprintln(os.Stderr, "\nRun 'mtls <subcommand> -h' for a subcommand's flags.")
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	name := os.Args[1]
	if name == "-h" || name == "--help" || name == "help" {
		usage()
		return
	}
	for _, c := range subcommands() {
		if c.name == name {
			if err := c.run(os.Args[2:]); err != nil {
				fmt.Fprintf(os.Stderr, "\nerror: %s\n", err)
				os.Exit(1)
			}
			return
		}
	}
	fmt.Fprintf(os.Stderr, "unknown subcommand %q\n\n", name)
	usage()
	os.Exit(2)
}
