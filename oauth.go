package mergeitis

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
	"google.golang.org/appengine"
	"google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/urlfetch"
	"io/ioutil"
	"net/http"
	"time"

	"mergeitis/config"
)

var (
	TimeFormat = "20060102"
	CookieName = "muid"
)

var conf = &oauth2.Config{
	ClientID:     config.GitHubClientID,
	ClientSecret: config.GitHubClientSecret,
	Scopes:       []string{"user:email"},
	Endpoint:     github.Endpoint,
	RedirectURL:  config.OAuthRedirectURL,
}

type GitHubUser struct {
	UID         []byte
	AccessToken string
	TokenType   string
}

func SignHmac(c context.Context, uid []byte) []byte {
	mac := hmac.New(sha256.New, []byte(conf.ClientSecret))
	mac.Write(uid)

	now := time.Now().UTC()

	mac.Write([]byte(now.Format(TimeFormat)))
	return mac.Sum(nil)
}

func GenerateUID(c context.Context) []byte {
	size := 32
	rb := make([]byte, size)
	_, err := rand.Read(rb)

	if err != nil {
		log.Errorf(c, "Error generating UID %v", err)
	}
	return rb
}

func GetMUID(c context.Context, r *http.Request) ([]byte, error) {
	cookie, err := r.Cookie(CookieName)
	if err != nil {
		log.Errorf(c, "Error getting cookie %v", err)
		return nil, err
	}

	uid_str := cookie.Value
	uid, err := base64.StdEncoding.DecodeString(uid_str)
	if err != nil {
		log.Errorf(c, "Error decoding cookie value %v", err)
		return nil, err
	}

	return uid, nil
}

func ValidateSignature(c context.Context, r *http.Request) error {
	secret_str := r.FormValue("state")
	secret, err := base64.StdEncoding.DecodeString(secret_str)
	if err != nil {
		log.Errorf(c, "Error decoding secret %v", err)
		return err
	}

	uid, err := GetMUID(c, r)
	if err != nil {
		log.Errorf(c, "Error getting UID %v", err)
		return err
	}

	secret_check := SignHmac(c, uid)
	if !hmac.Equal(secret, secret_check) {
		log.Errorf(c, "Invalid state")
		return errors.New("Invalid state")
	}

	return nil
}

func HandlerSignIn(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	uid := GenerateUID(c)
	secret := SignHmac(c, uid)

	uid_str := base64.StdEncoding.EncodeToString(uid)
	secret_str := base64.StdEncoding.EncodeToString(secret)

	expiration := time.Now().Add(24 * time.Hour)
	cookie := &http.Cookie{
		Domain:  config.BaseURL,
		Name:    CookieName,
		Value:   uid_str,
		Path:    "/",
		Expires: expiration,
		MaxAge:  7200,
		Secure:  true,
	}

	url := conf.AuthCodeURL(secret_str, oauth2.AccessTypeOffline)

	http.SetCookie(w, cookie)
	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

func HandlerOAuth(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	err := ValidateSignature(c, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	code := r.FormValue("code")
	token, err := conf.Exchange(c, code)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	uid, _ := GetMUID(c, r)

	user := GitHubUser{
		AccessToken: token.AccessToken,
		TokenType:   token.TokenType,
	}

	key := datastore.NewKey(c, "GitHubUser", string(uid), 0, nil)
	if _, err := datastore.Put(c, key, &user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	log.Infof(c, "Got the token")
	http.Redirect(w, r, "/user", http.StatusTemporaryRedirect)
}

func HandlerUser(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)

	uid, err := GetMUID(c, r)
	if err != nil {
		http.Redirect(w, r, "/signin", http.StatusTemporaryRedirect)
		return
	}

	key := datastore.NewKey(c, "GitHubUser", string(uid), 0, nil)
	user := new(GitHubUser)
	if err = datastore.Get(c, key, user); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	client := urlfetch.Client(c)
	req, err := http.NewRequest("GET", "https://api.github.com/user", nil)
	req.Header.Set("Authorization", fmt.Sprintf("%s %s", user.TokenType, user.AccessToken))

	resp, err := client.Do(req)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	res := make(map[string]interface{}, 0)
	json.Unmarshal(body, &res)
	fmt.Fprint(w, fmt.Sprintf("Hello %s", res["name"]))
}
