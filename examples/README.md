# Running Examples for MSAL Go

To run one of the examples of uses of MSAL Go, you need to first create a `config.json` file. The `config.json` file should look like the following:
```json
{
    "authority": "https://login.microsoftonline.com/organizations",
    "client_id": "your_client_id",
    "scopes": ["user.read"],
        // You can find the other permission names from this document
        // https://docs.microsoft.com/en-us/graph/permissions-reference
    "username": "your_username",
    "password": "your_password", //This is a sample only. DO NOT persist your password.
    "redirect_uri": "The URL that the authorization server will send the user to once the app has been successfully authorized, and granted an authorization code",
    "code_challenge": "transformed code verifier from PKCE", // https://tools.ietf.org/html/rfc7636#section-4.1
    "code_challenge_method": "how to transform the code verifier"
}
```

To run one of the examples, run the command `go run src/examples/*.go <example-arg>`. The example arguments are as follows:
* 1 - `device_code_flow_sample.go` 
* 2 - `authorization_code_sample.go`
