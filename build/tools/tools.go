//go:build tools
// +build tools

// Package tools pins the versions of the build/test tooling used by CI
// (currently gotestsum) so they are installed from a committed lock file
// (go.sum) instead of being resolved at run time via "go install pkg@version".
//
// This module is intentionally separate from the main module: it keeps the
// tooling's dependency graph out of the published library and lets the pipeline
// run a lock-file-enforcing install, e.g.:
//
//	go -C build/tools install gotest.tools/gotestsum
//
// The blank import below keeps gotestsum in this module's dependency graph so
// "go mod tidy" retains it and go.sum stays complete.
package tools

import (
	// These blank imports keep gotestsum's command packages (and their
	// transitive dependencies) in this module's graph so "go mod tidy" retains
	// them and go.sum stays complete, which lets CI run a lock-file-enforcing
	// "go install gotest.tools/gotestsum".
	_ "gotest.tools/gotestsum/cmd"              // root "gotestsum" command
	_ "gotest.tools/gotestsum/cmd/tool/matrix"  // "gotestsum tool ci-matrix"
	_ "gotest.tools/gotestsum/cmd/tool/slowest" // "gotestsum tool slowest"
)
