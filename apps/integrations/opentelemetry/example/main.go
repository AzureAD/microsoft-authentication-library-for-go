// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/AzureAD/microsoft-authentication-library-for-go/apps/confidential"
	msalotel "github.com/AzureAD/microsoft-authentication-library-for-go/apps/integrations/opentelemetry"
	"go.opentelemetry.io/otel/exporters/stdout/stdoutmetric"
	"go.opentelemetry.io/otel/sdk/metric"
)

func main() {
	if err := run(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context) error {
	tenantID := os.Getenv("AZURE_TENANT_ID")
	clientID := os.Getenv("AZURE_CLIENT_ID")
	clientSecret := os.Getenv("AZURE_CLIENT_SECRET")
	if tenantID == "" || clientID == "" || clientSecret == "" {
		return fmt.Errorf("AZURE_TENANT_ID, AZURE_CLIENT_ID, and AZURE_CLIENT_SECRET must be set")
	}

	exporter, err := stdoutmetric.New(stdoutmetric.WithPrettyPrint())
	if err != nil {
		return err
	}
	reader := metric.NewPeriodicReader(exporter, metric.WithInterval(time.Second))
	meterProvider := metric.NewMeterProvider(metric.WithReader(reader))
	defer func() {
		_ = meterProvider.Shutdown(context.Background())
	}()
	recorder, err := msalotel.New(meterProvider)
	if err != nil {
		return err
	}

	authority := "https://login.microsoftonline.com/" + tenantID
	credential, err := confidential.NewCredFromSecret(clientSecret)
	if err != nil {
		return err
	}
	client, err := confidential.New(
		authority,
		clientID,
		credential,
		confidential.WithMetricsRecorder(recorder),
	)
	if err != nil {
		return err
	}
	scopes := []string{"https://graph.microsoft.com/.default"}

	fmt.Println("Acquiring from the identity provider...")
	if _, err = client.AcquireTokenByCredential(ctx, scopes); err != nil {
		return err
	}
	fmt.Println("Acquiring the same token from cache...")
	if _, err = client.AcquireTokenByCredential(ctx, scopes); err != nil {
		return err
	}

	fmt.Println("Generating a sanitized authentication failure...")
	invalidCredential, err := confidential.NewCredFromSecret("intentionally-invalid")
	if err != nil {
		return err
	}
	invalidClient, err := confidential.New(
		authority,
		clientID,
		invalidCredential,
		confidential.WithMetricsRecorder(recorder),
	)
	if err != nil {
		return err
	}
	_, _ = invalidClient.AcquireTokenByCredential(ctx, scopes)

	return meterProvider.ForceFlush(ctx)
}
