# Running Examples for MSAL Go

To run one of the examples of uses of MSAL Go, you need to first create a `config.json` file. The `config.json` file should look like the following:
```json
{
    "authority": "https://login.microsoftonline.com/organizations",
    "client_id": "your_client_id",
    "scopes": ["user.read"],
    "username": "your_username",
    "password": "your_password",
    "redirect_uri": "The URL that the authorization server will send the user to once the app has been successfully authorized, and granted an authorization code",
    "code_challenge": "transformed code verifier from PKCE",  
    "state": "state parameter for authorization code flow",
    "client_secret": "client secret you generated for your app",
    "thumbprint": "the certificate thumbprint defined in your app generation",
    "pem_file": "the file path of your private key pem"
}
```

To find permissible scopes, visit this [link](https://docs.microsoft.com/en-us/graph/permissions-reference). PKCE is explained [here](https://tools.ietf.org/html/rfc7636#section-4.1).

To run one of the examples, run the command `go run src/examples/*.go <example-arg>`. The example arguments are as follows:
* 1 - `device_code_flow_sample.go` 
* 2 - `authorization_code_sample.go`
* 3 - `username_password_sample.go`
* 4 - `confidential_auth_code_sample.go`
* 5 - `client_secret_sample.go`
* 6 - `client_certificate_sample.go`
