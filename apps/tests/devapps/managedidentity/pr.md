# Pull Request

## Description

This pull request introduces changes to the `ID` interface and its implementations to ensure that `SystemAssigned` always returns `"system_assigned_managed_identity"` and other types return their respective values. These changes are particularly relevant for Azure Arc scenarios where different types of managed identities need to be handled consistently.

## Changes

- **ID Interface**: Modified the `ID` interface to include a `String` method, ensuring all identity types can return a string representation.
- **SystemAssigned**: Implemented the `String` method for `systemAssignedValue` to always return `"system_assigned_managed_identity"`.
- **ClientID, ObjectID, ResourceID**: Implemented the `String` method for `ClientID`, `ObjectID`, and `ResourceID` types to return their respective values.
- **New Function**: Updated the `New` function to use the `String` method for printing the identity type, ensuring consistent behavior across different identity types.

## Azure Arc Context

These changes are crucial for Azure Arc-enabled environments where managed identities are used to authenticate and authorize resources. By ensuring that `SystemAssigned` always returns a consistent string and other types return their provided values, we improve the reliability and predictability of identity management in Azure Arc scenarios.

## Testing

- **Unit Tests**: Added unit tests to verify that `SystemAssigned` returns `"system_assigned_managed_identity"`.
- **Integration Tests**: Added integration tests to verify that `ClientID`, `ObjectID`, and `ResourceID` return their respective values in Azure Arc-enabled environments.

## Checklist

- [x] Code compiles correctly
- [x] All tests passing
- [x] Extended the documentation, if necessary

## Related Issues

- Closes #<issue_number>


GetSource
AcquireToken
getAzureArcEnvironmentVariables
validateAzureArcEnvironment
fileExists
handleAzureArcResponse