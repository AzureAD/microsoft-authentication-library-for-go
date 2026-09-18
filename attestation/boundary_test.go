// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package attestation

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const (
	coreModulePath        = "github.com/AzureAD/microsoft-authentication-library-for-go"
	attestationModulePath = coreModulePath + "/attestation"
)

func TestCoreManagedIdentityDoesNotDependOnOptionalModule(t *testing.T) {
	cmd := exec.Command("go", "list", "-mod=readonly", "-deps", coreModulePath+"/apps/managedidentity")
	cmd.Env = append(os.Environ(), "GOWORK=off")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go list core managedidentity dependencies: %v\n%s", err, output)
	}
	for _, dependency := range strings.Fields(string(output)) {
		if dependency == attestationModulePath || strings.HasPrefix(dependency, attestationModulePath+"/") {
			t.Fatalf("core managedidentity depends on optional package %q", dependency)
		}
	}
}

func TestWindowsBinaryEmbeddingBoundary(t *testing.T) {
	attestationDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	coreDir := filepath.Dir(attestationDir)
	//nolint:gosec // This is the repository-owned native fixture at a fixed relative path.
	dll, err := os.ReadFile(filepath.Join(attestationDir, "native", dllNameForTest))
	if err != nil {
		t.Fatal(err)
	}

	plain := buildTestApplication(t, coreDir, attestationDir, false)
	if bytes.Contains(plain, dll) {
		t.Fatal("ordinary MSAL application binary contains the optional attestation DLL")
	}
	optedIn := buildTestApplication(t, coreDir, attestationDir, true)
	if !bytes.Contains(optedIn, dll) {
		t.Fatal("opted-in Windows application binary does not contain the embedded attestation DLL")
	}
}

const dllNameForTest = "AttestationClientLib.dll"

func buildTestApplication(t *testing.T, coreDir, attestationDir string, optedIn bool) []byte {
	t.Helper()
	dir := t.TempDir()
	requirement := fmt.Sprintf("require %s v0.0.0\n", coreModulePath)
	replacement := fmt.Sprintf("replace %s => %s\n", coreModulePath, filepath.ToSlash(coreDir))
	source := `package main

import (
	"context"
	"os"

	managedidentity "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

var options = []managedidentity.AcquireTokenOption{managedidentity.WithMtlsProofOfPossession()}

func main() {
	if os.Getenv("RUN_MANAGED_IDENTITY") != "" {
		client, err := managedidentity.New(managedidentity.SystemAssigned())
		if err != nil {
			panic(err)
		}
		_, _ = client.AcquireToken(context.Background(), "https://vault.azure.net", options...)
	}
}
`
	if optedIn {
		requirement = fmt.Sprintf(`require (
	%s v0.0.0
	%s v0.0.0
)
`, coreModulePath, attestationModulePath)
		replacement += fmt.Sprintf("replace %s => %s\n", attestationModulePath, filepath.ToSlash(attestationDir))
		source = `package main

import (
	"context"
	"os"

	managedidentity "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
	"github.com/AzureAD/microsoft-authentication-library-for-go/attestation"
)

var options = []managedidentity.AcquireTokenOption{
	managedidentity.WithMtlsProofOfPossession(),
	attestation.WithSupport(),
}

func main() {
	if os.Getenv("RUN_MANAGED_IDENTITY") != "" {
		client, err := managedidentity.New(managedidentity.SystemAssigned())
		if err != nil {
			panic(err)
		}
		_, _ = client.AcquireToken(context.Background(), "https://vault.azure.net", options...)
	}
}
`
	}
	goMod := "module embeddingtest\n\ngo 1.18\n\n" + requirement + "\n" + replacement
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(goMod), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	outputPath := filepath.Join(dir, "application.exe")
	//nolint:gosec // The command and arguments are fixed; only the isolated test directory varies.
	cmd := exec.Command("go", "build", "-mod=mod", "-trimpath", "-o", outputPath, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"GOOS=windows",
		"GOARCH=amd64",
		"CGO_ENABLED=0",
		"GOWORK=off",
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building optedIn=%t Windows application: %v\n%s", optedIn, err, output)
	}
	//nolint:gosec // outputPath is the fixed build output inside t.TempDir.
	binary, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	return binary
}
