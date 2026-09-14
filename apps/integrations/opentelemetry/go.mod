module github.com/AzureAD/microsoft-authentication-library-for-go/apps/integrations/opentelemetry

go 1.25.0

require (
	github.com/AzureAD/microsoft-authentication-library-for-go v1.10.0
	go.opentelemetry.io/otel v1.46.0
	go.opentelemetry.io/otel/metric v1.46.0
	go.opentelemetry.io/otel/sdk/metric v1.46.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/otel/sdk v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)

// The replacement supports development in this repository. Downstream modules
// resolve the released parent module version above because dependency replace
// directives aren't inherited.
replace github.com/AzureAD/microsoft-authentication-library-for-go => ../../..
