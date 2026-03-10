// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package managedidentity_test

import (
	"fmt"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

// This example demonstrates how to create the managed identity client with system assigned
//
// A system-assigned managed identity is enabled directly on an Azure resource (like a VM, App Service, or Function).
// Azure automatically creates this identity and ties it to the lifecycle of the resource — it gets deleted when the resource is deleted.
// Use this when your app only needs one identity and doesn’t need to share it across services.
// Learn more:
// https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview#system-assigned-managed-identity
func ExampleNew_systemAssigned() {
	systemAssignedClient, err := mi.New(mi.SystemAssigned())
	if err != nil {
		fmt.Printf("failed to create client with system-assigned identity: %v", err)
	}
	_ = systemAssignedClient // Use this client to authenticate to Azure services (e.g., Key Vault, Storage, etc.)

}

// This example demonstrates how to create the managed identity client with user assigned
//
// A user-assigned managed identity is a standalone Azure resource that can be assigned to one or more Azure resources.
// User-assigned identities: https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview#user-assigned-managed-identity
func ExampleNew_userAssigned() {
	clientID := "your-user-assigned-client-id" // TODO: Replace with actual managed identity client ID

	userAssignedClient, err := mi.New(
		mi.UserAssignedClientID(clientID),
	)
	if err != nil {
		fmt.Printf("failed to create client with user-assigned identity: %v", err)
	}
	_ = userAssignedClient // Use this client for authentication when stable or shared identity is required
}

// Client Capabilities ("cp1", etc.)
// 'cp1' is a capability that enables specific client behaviors — for example,
// supporting Conditional Access policies that require additional client capabilities.
// This is mostly relevant in scenarios where the identity is used to access resources
// protected by policies like MFA or device compliance.
// In most cases, you won't need to set this unless required by your Azure AD configuration.
//
// Learn more:
// Client capabilities: https://learn.microsoft.com/entra/msal/python/advanced/client-capabilities
func ExampleWithClientCapabilities() {
	clientID := "your-user-assigned-client-id" // TODO: Replace with actual managed identity client ID

	userAssignedClient, err := mi.New(
		mi.UserAssignedClientID(clientID),

		mi.WithClientCapabilities([]string{"cp1"}),
	)
	if err != nil {
		fmt.Printf("failed to create client with user-assigned identity: %v", err)
	}
	_ = userAssignedClient // Use this client for authentication when stable or shared identity is required
}
