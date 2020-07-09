// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.

package msalbase

//DefaultAuthCodeResponseType is the response type for authorization code requests
const DefaultAuthCodeResponseType = "code"

//DefaultScopeSeparator is used to convert a list of scopes to a string
const DefaultScopeSeparator = " "

//IntervalAddition is used in device code requests to increase the polling interval if there is a slow down error
const IntervalAddition = 5

//CacheKeySeparator is used in creating the keys of the cache
const CacheKeySeparator = "-"

//AppMetadataCacheID is a part of the cache key for App Metadata items
const AppMetadataCacheID = "appmetadata"
