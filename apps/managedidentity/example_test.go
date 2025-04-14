// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

package managedidentity_test

import (
	"fmt"

	mi "github.com/AzureAD/microsoft-authentication-library-for-go/apps/managedidentity"
)

func ExampleNew() {
	// ===============================
	// System-Assigned Managed Identity
	// ===============================

	// A system-assigned managed identity is enabled directly on an Azure resource (like a VM, App Service, or Function).
	// Azure automatically creates this identity and ties it to the lifecycle of the resource — it gets deleted when the resource is deleted.
	// Use this when your app only needs one identity and doesn’t need to share it across services.
	systemAssignedClient, err := mi.New(mi.SystemAssigned())
	if err != nil {
		fmt.Printf("failed to create client with system-assigned identity: %v", err)
	}
	_ = systemAssignedClient // Use this client to authenticate to Azure services (e.g., Key Vault, Storage, etc.)

	// Learn more:
	// https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview#system-assigned-managed-identity

	// =============================
	// User-Assigned Managed Identity
	// =============================

	// A user-assigned managed identity is a standalone Azure resource that can be assigned to one or more Azure resources.
	// It's ideal when:
	// - You need a consistent identity across services (e.g., multiple apps accessing the same Key Vault)
	// - You want to control the lifecycle of the identity independently of the resource
	// - You need fine-grained role assignments or separation of concerns

	clientID := "your-user-assigned-client-id" // TODO: Replace with actual managed identity client ID

	userAssignedClient, err := mi.New(
		mi.UserAssignedClientID(clientID),

		// ===========================================
		// Optional: Client Capabilities ("cp1", etc.)
		// ===========================================

		// 'cp1' is a capability that enables specific client behaviors — for example,
		// supporting Conditional Access policies that require additional client capabilities.
		// This is mostly relevant in scenarios where the identity is used to access resources
		// protected by policies like MFA or device compliance.

		// In most cases, you won't need to set this unless required by your Azure AD configuration.
		mi.WithClientCapabilities([]string{"cp1"}),
	)
	if err != nil {
		fmt.Printf("failed to create client with user-assigned identity: %v", err)
	}
	_ = userAssignedClient // Use this client for authentication when stable or shared identity is required

	// Learn more:
	// - User-assigned identities: https://learn.microsoft.com/azure/active-directory/managed-identities-azure-resources/overview#user-assigned-managed-identity
	// - Client capabilities: https://learn.microsoft.com/azure/active-directory/develop/msal-client-capabilities
}
