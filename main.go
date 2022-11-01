package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/lestrrat-go/jwx/jwk"
)

const (
	CodeVerifierCookieName = "code_verifier"
	AccessTokenCookieName = "access_token"
	TemplatesFolder = "templates"
)

var client = http.Client{}

var Port string
var ClientID string
var Issuer string


func main() {
	Port = os.Getenv("PORT")
	ClientID = os.Getenv("CLIENT_ID")
	Issuer = os.Getenv("ISSUER")

	rand.Seed(time.Now().UnixNano())

	http.HandleFunc("/", HandleHome)
	http.HandleFunc("/login", HandleLogin)
	http.HandleFunc("/logout", HandleLogout)
	http.HandleFunc("/callback", HandleCallback)

	http.ListenAndServe(fmt.Sprintf(":%s", Port), nil)
}

// HandleHome renders the homepage which has links for logging in/out 
func HandleHome(w http.ResponseWriter, r *http.Request) {
	authCookie, err := r.Cookie(AccessTokenCookieName)

	if err != nil {
		renderTemplate(w, "index.html", struct { Subject string }{ 
			Subject: "",
		})

		return
	}

	token, err := jwt.Parse(authCookie.Value, getTokenKey)

	if err != nil {
		authFailed(w, fmt.Errorf("there was an access token in the request but it was invalid"))
	}

	claims := token.Claims.(jwt.MapClaims)

	renderTemplate(w, "index.html", struct { Subject string }{ 
		Subject: claims["sub"].(string),
	})
}

// HandleCallback handles the redirect from the /authorize endpoint and exchanges the auth code for an access token
func HandleCallback(w http.ResponseWriter, r *http.Request) {
	// retrieve the auth code from the querystring
	code, ok := r.URL.Query()["code"]

	if !ok || len(code) != 1 {
		authFailed(w, fmt.Errorf("code not present in query or invalid"))

		return
	}

	// grab the code verifier cookie we stored at /login
	cvCookie, err := r.Cookie(CodeVerifierCookieName)

	if err != nil {
		authFailed(w, err)

		return
	}

	// make a request to /token to exchange the auth code and verifier for an access token
	response, err := requestToken(code[0], cvCookie.Value, getSelfRedirectURI(r))

	if err != nil {
		authFailed(w, err)

		return
	}

	// extract a JWT token from the response
	token, err := extractJWT(response)

	if err != nil {
		authFailed(w, err)

		return
	}

	// set the access token cookie
	http.SetCookie(w, &http.Cookie{ 
		Name: AccessTokenCookieName, 
		Value: token.Raw, 
		HttpOnly: true, 
		Secure: true,
	})

	// remove the code verifier cookie
	http.SetCookie(w, &http.Cookie{ Name: CodeVerifierCookieName, Expires: time.Now().Add(time.Minute * -1) })

	// send the client to homepage
	http.Redirect(w, r, "/", http.StatusFound)
}

// HandleLogin generates PKCE tokens and sends the client to the /authorize endpoint
func HandleLogin(w http.ResponseWriter, r *http.Request) {
	// generate a code verifier, a random sequence of bytes with enough entropy to be hard to guess
	codeVerifier := randSeq(48)

	fmt.Printf("on login, codeVerifier=[%s]\n", codeVerifier)

	// generate the code challenge by applying the pseudo-code: BASE64URL-ENCODE(SHA256(ASCII(code_verifier)))
	// https://datatracker.ietf.org/doc/html/rfc7636
	codeChallengeBytes := []byte(codeVerifier)
	codeChallengeHash := sha256.Sum256(codeChallengeBytes)
	codeChallenge := strings.Trim(base64.URLEncoding.EncodeToString(codeChallengeHash[:]), "=")

	fmt.Printf("on login, codeChallenge=[%s]\n", codeChallenge)

	// construct the URI for the authorize endpoint
	redirectUri := fmt.Sprintf(
		"%s/oauth2/authorize?%s",
		Issuer,
		createAuthQuery(ClientID, getSelfRedirectURI(r), codeChallenge),
	)

	fmt.Printf("on login, redirectUri=[%s]\n", redirectUri)

	// set a cookie with the code verifier so we can retrieve it later after redirect
	http.SetCookie(w, &http.Cookie{Name: "code_verifier", Value: codeVerifier, Secure: true, HttpOnly: true})

	// send the client off to the authorize endpoint
	http.Redirect(w, r, redirectUri, http.StatusFound)
}

// HandleLogout logs the user out by removing the access_token cookie
func HandleLogout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{ Name: AccessTokenCookieName, Expires: time.Now().Add(time.Minute * -1) })
	http.Redirect(w, r, "/", http.StatusFound)
}

// renderTemplate is a helper method to render a HTML template
func renderTemplate(w http.ResponseWriter, name string, data interface{}) {
	tpl, err := template.ParseFiles(path.Join(TemplatesFolder, name))
	
	if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			
			return
	}

	if err := tpl.Execute(w, data); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// authFailed prints the error to the console and returns an authentication failed message to the client
func authFailed(w http.ResponseWriter, err error) {
	fmt.Println(err)

	w.WriteHeader(http.StatusInternalServerError)

	fmt.Fprint(w, "Authentication Failed!")
}

// requestToken constructs and sends a request to the /token endpoint and returns the response
func requestToken(code, codeVerifier, redirectUri string) (*http.Response, error) {
	
	// contruct the request to /token to retrieve an access token
	tokenBody := createTokenQuery(code, codeVerifier, redirectUri)
	tokenUri := fmt.Sprintf("%s/oauth2/token", Issuer)

	request, err := http.NewRequest("POST", tokenUri, bytes.NewBuffer([]byte(tokenBody)))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	fmt.Printf("tokenUri=[%s]\n", tokenUri)

	if err != nil {
		return nil, err
	}

	// send the /token request
	response, err := client.Do(request)

	if err != nil {
		return nil, err
	}

	if response.StatusCode != 200 {
		body, err := io.ReadAll(response.Body)

		if err != nil {
			return nil, fmt.Errorf("token call failed with status=[%d], in addition failed to read response body with error=[%w]", response.StatusCode, err)
		} else {
			return nil, fmt.Errorf("token call failed with status=[%d], message=[%s]", response.StatusCode, body)
		}
	}

	return response, nil
}

// createAuthQuery creates the querystring needed to call an oauth2 /authorize endpoint for PKCE flow
func createAuthQuery(clientId, redirectUri, codeChallenge string) string {
	query := url.Values{}

	query.Add("client_id", clientId)
	query.Add("redirect_uri", redirectUri)
	query.Add("scope", "openid email profile")
	query.Add("response_type", "code")
	query.Add("response_mode", "query")
	query.Add("code_challenge", codeChallenge)
	query.Add("code_challenge_method", "S256")

	return query.Encode()
}

// createTokenQuery creates the querystring needed to call an oauth2 /token endpoint for auth code exchange
func createTokenQuery(code, codeVerifier, redirectUri string) string {
	query := url.Values{}

	query.Add("grant_type", "authorization_code")
	query.Add("code", code)
	query.Add("code_verifier", codeVerifier)
	query.Add("client_id", ClientID)
	query.Add("redirect_uri", redirectUri)

	return query.Encode()
}

// extractJWT takes a *http.Response and extracts the 'access_token' field as a *jwt.Token
func extractJWT(response *http.Response) (*jwt.Token, error) {
	var body struct {
		AccessToken string `json:"access_token"`
	}

	bodyBytes, err := io.ReadAll(response.Body)

	if err != nil {
		return nil, fmt.Errorf("got a successful token response, but failed to read response body, error=[%w]", err)
	}

	err = json.Unmarshal(bodyBytes, &body)

	if err != nil {
		return nil, fmt.Errorf("got successful token response, but failed to unmarshal body to json struct, error=[%w]", err)
	}

	token, err := jwt.Parse(body.AccessToken, getTokenKey)

	if err != nil {
		return nil, fmt.Errorf("got a token, but failed parse it using the keyset url: %w", err)
	}

	return token, nil
}

// getTokenKey takes a JWT token and returns the matching signing key from the JWK URI
func getTokenKey(jwt *jwt.Token) (interface{}, error) {
	keys, err := jwk.Fetch(context.TODO(), fmt.Sprintf("%s/oauth2/v1/keys", Issuer))

	if err != nil {
		return nil, err
	}

	kid, ok := jwt.Header["kid"]

	if !ok {
		return nil, fmt.Errorf("expected token to have header 'kid'")
	}

	key, ok := keys.LookupKeyID(kid.(string))

	if !ok {
		return nil, fmt.Errorf("did not find a key matching token kid in the keyset")
	}

	var publicKey interface{}
	
	err = key.Raw(&publicKey)

	if err != nil {
		return nil, err
	}

	return publicKey, nil
}

func getSelfRedirectURI(r *http.Request) string {
	return fmt.Sprintf("http://%s/callback", r.Host)
}

var letters = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890")
// https://stackoverflow.com/questions/22892120/how-to-generate-a-random-string-of-a-fixed-length-in-go/22892986#22892986
func randSeq(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
