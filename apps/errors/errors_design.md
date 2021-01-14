# MSAL Error Design

Errors in MSAL are intended for app developers to troubleshoot and not for displaying to end-users. Go has a different approach to error handling than others

## MSALClientError

MSAL throws MsalClientError for things that go wrong inside the library (e.g. bad configuration). MSALClientError is a struct that looks like this:

``` Go
type struct MSALClientEror {
    ErrorCode string
    Message string
}
```

The error code to be displayed for client errors is derived from the this list : [MSALError](https://docs.microsoft.com/en-us/dotnet/api/microsoft.identity.client.msalerror?view=azure-dotnet#fields).
Reference to the defined list of codes can also be found [here](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/blob/c49e2c6f85408df3d207f05cf0214430ab83bda6/src/client/Microsoft.Identity.Client/MsalError.cs#L11).

## MSALServiceError

MSAL ServiceError is an error that is returned for things that go wrong service side.The json conversion of an Error response from the service looks like this.

``` Go
type struct ErrorResponse {
    ErrorCode       string `json:"error"`
    ErrorDescription   string `json:"error_description"`
    ErrorCodes    []string `json: "error_codes"`
    SubError      string `json:"suberror"`
    Timestamp     string `json:"timestamp"`
    TraceID       string `json:"trace_id"`
    CorrelationID string `json:"correlation_id"`
    URL           string `json:"error_uri"`
    Claims        string `json:"claims"`
}
```

MSAL fetches fields from the ErrorResponse to be exposed to the client in the form of MSALServiceError which will look like this:

``` Go
type struct MSALServiceError {
    ErrorCode string // Error code from the json response
    ErrorDescription string // Description from the json response
    CorrelationID string // An ID that can be used to piece up a single authentication flow
    Claims string // Claims included in the claims challenge
    Resp *http.Response // Http response from the server
}
```

The Error function on this error will use the Message and Description from the Error Response as the error message. All the other fields can be fetched from the struct object.

## MSALInteractionRequiredError

The "InteractionRequired" is proposed as a specialization of MsalServiceError named MsalInteractionRequiredError. This means you have attempted to use a non-interactive method of acquiring a token (e.g. AcquireTokenSilent), but MSAL could not do it silently. this can be because:

* you need to sign-in
* you need to consent
* you need to go through a multi-factor authentication experience.

The MSALUIRequiredError will expose a field called `Classification` which is fetched from the sub_error field of the `ErrorResponse`. This field will only be populated for certain scenarios as explained:

MSAL exposes  `Classification` field, which you can read to provide a better user experience, for example to tell the user that his password expired or that he will need to provide consent to use some resources.
More to see supported values of classification field [here](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/wiki/MsalUiRequiredException-classification).

More details on when and why this is required [here](https://github.com/AzureAD/microsoft-authentication-library-for-dotnet/issues/1148)

``` Go
type struct MSALUIRequiredException {
    MSALServiceError MSALServiceError
    Classification string
}
```
