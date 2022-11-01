# Go PKCE Sample
This sample contains example code written in Golang to perform an OAuth2 'Authorization Code with PKCE' flow.

The standard net/http library is used to handle HTTP request/response and two JWT related libraries are used to parse and validate the JWT tokens.

# How to run the sample
Export the required environment variables
```
export ISSUER=<issuer URI of your OAuth2 IdP>
export CLIENT_ID=<your apps client id>
export PORT=8089
```
Install modules and run the server
```
go mod tidy
go run main.go
```
Finally, to view the sample in action, browse to http://localhost:\<PORT\>

# How to run the sample using VSCODE
If you're using VSCODE, a `launch.json` has been provided. Simply copy `.env.sample` to `.env` and update the values as indicated in the env vars above. Then, F5 should run the server.

---
_DISCLAIMER: This code should be used as a guide only and has not been thoroughly evaluated for it's security best practise. Use at your own risk._