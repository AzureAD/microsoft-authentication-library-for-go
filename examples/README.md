# Running Examples for MSAL Go

To run one of the examples of uses of MSAL Go. The `config.json` file and the `confidential_config.json` should look like the following:

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

The samples in this repo get tokens for the MS Graph API. To find permissible scopes for MS Graph, visit this [link](https://docs.microsoft.com/graph/permissions-reference). PKCE is explained [here](https://tools.ietf.org/html/rfc7636#section-4.1).

## On Windows

To run the examples:
    `cd examples`
  
run the command:
    `go run main.go sample_utils.go sample_cache_accessor.go device_code_flow_sample.go authorization_code_sample.go client_secret_sample.go confidential_auth_code_sample.go username_password_sample.go client_certificate_sample.go <example-number>`

For example to run device code flow use this command:
    `go run main.go sample_utils.go sample_cache_accessor.go device_code_flow_sample.go authorization_code_sample.go client_secret_sample.go confidential_auth_code_sample.go username_password_sample.go client_certificate_sample.go 1`
    
Alternatives:
* 1 build and run "locally"
  * In the examples folder
  * type 'go build' 
  * type 'examples.exe 1' to run the device code flow

* 2 install and run from the gobin folder
  * In the examples folder
  * type 'go install' 
  * locate your gobin folder e.g. type 'go env' to find your gobin folder location
  cd to your gobin folder
  * type 'examples.exe 1' to run the device code flow
  
## On Mac

To run one of the examples, run the command `go run src/examples/*.go <example-number>`. The example numbers are as follows:

* 1 - `device_code_flow_sample.go` 
* 2 - `authorization_code_sample.go`
* 3 - `username_password_sample.go`
* 4 - `confidential_auth_code_sample.go`
* 5 - `client_secret_sample.go`
* 6 - `client_certificate_sample.go`
