# Running the Dev Apps for MSAL Go

To run one of the dev app which uses MSAL Go, the `config.json` file and the `confidential_config.json` should look like the following:

```json
{
    "authority": "https://login.microsoftonline.com/organizations",
    "client_id": "your_client_id",
    "scopes": ["user.read"],
    "username": "your_username",
    "password": "your_password",
    "redirect_uri": "redirect uri registered on the portal",
    "code_challenge": "transformed code verifier from PKCE",  
    "state": "state parameter for authorization code flow",
    "client_secret": "client secret you generated for your app",
    "thumbprint": "the certificate thumbprint defined in your app generation",
    "pem_file": "the file path of your private key pem"
}
```

The dev apps in this repo get tokens for the MS Graph API. To find permissible scopes for MS Graph, visit this [link](https://docs.microsoft.com/graph/permissions-reference). PKCE is explained [here](https://tools.ietf.org/html/rfc7636#section-4.1).

## On Windows

To run the dev samples:
    `cd test/devapps`
  
run the command:
    
    'go run ./ 1'
    
Alternatives:
* 1 build and run "locally"
  * In the devapps folder
  * type 'go build' 
  * type 'devapps.exe 1' to run the device code flow

* 2 (Advanced) install and run from the gobin folder
  * See more: https://golang.org/cmd/go/#hdr-Compile_and_install_packages_and_dependencies
  * In the devapps folder
  * type 'go install' 
  * locate your gobin folder e.g. type 'go env' to find your gobin folder location
  cd to your gobin folder
  * type 'devapps.exe 1' to run the device code flow
  
## On Mac

To run one of the devapps, run the command `go run src/test/devapps/*.go <devapps-number>`. The devapp numbers are as follows:

* 1 - `device_code_flow_sample.go` 
* 2 - `authorization_code_sample.go`
* 3 - `username_password_sample.go`
* 4 - `confidential_auth_code_sample.go`
* 5 - `client_secret_sample.go`
* 6 - `client_certificate_sample.go`
