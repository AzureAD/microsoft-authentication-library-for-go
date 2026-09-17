module github.com/AzureAD/microsoft-authentication-library-for-go/apps/integrations/opentelemetry/example

go 1.25.0

require (
	github.com/AzureAD/microsoft-authentication-library-for-go v1.10.0
	github.com/AzureAD/microsoft-authentication-library-for-go/apps/integrations/opentelemetry v0.1.0
	go.opentelemetry.io/otel/exporters/stdout/stdoutmetric v1.46.0
	go.opentelemetry.io/otel/sdk/metric v1.46.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/sdk v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	golang.org/x/sync v0.10.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

replace github.com/AzureAD/microsoft-authentication-library-for-go => ../../../..

replace github.com/AzureAD/microsoft-authentication-library-for-go/apps/integrations/opentelemetry => ..
