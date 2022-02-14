package auth

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

// Token model
type tokenModel struct {
	Token     string    `json:"token"`
	Agent     string    `json:"agent"`
	ClientIP  string    `json:"client_ip"`
	UserId    int64     `json:"user_id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiredAt time.Time `json:"expired_at"`
}

// Authentication model
type Authentication struct {
	URL       string
	Token     string
	HaveToken bool
	IsAuth    bool
	IsExpired bool
	UserId    int64
}

// Create instance
func NewAuth(request *http.Request, URL string) Authentication {
	auth := authentication()
	return auth(request, URL)
}

func authentication() func(request *http.Request, URL string) Authentication {
	return func(request *http.Request, URL string) Authentication {
		var authentication Authentication
		// Set IsAuth
		// Set IsExpired
		// Set URL
		// Set If token found
		// Check token if found, not found or expired
		authentication.IsAuth = false
		authentication.IsExpired = false
		authentication.URL = URL
		authentication.SetTokenFromRequest(request)

		if authentication.HaveToken {
			authentication.checkToken()
		}

		return authentication
	}
}

// Set Token
func (auth *Authentication) SetTokenFromRequest(request *http.Request) {
	authorization := request.Header["Authorization"]
	if len(authorization) == 0 {
		auth.HaveToken = false
		return
	}
	token := strings.Split(authorization[0], " ")
	if token == nil {
		auth.HaveToken = false
		return
	}
	auth.Token = token[1]
	auth.HaveToken = true
}

// Check token if found or expired or available
func (auth *Authentication) checkToken() {
	var model tokenModel
	postBody, _ := json.Marshal(map[string]string{
		"token": auth.Token,
	})

	// Make Request
	resp, err := http.Post(auth.URL, "application/json", bytes.NewBuffer(postBody))
	if err != nil {
		auth.IsAuth = false
		return
	}
	defer resp.Body.Close()

	body, _ := ioutil.ReadAll(resp.Body)
	json.Unmarshal(body, &model)

	if model.Token != "" {
		duration := model.ExpiredAt.Sub(time.Now()).Hours()
		if duration <= 0 {
			auth.IsExpired = true
			auth.IsAuth = false
			return
		}
		auth.IsExpired = false
		auth.IsAuth = true
		auth.UserId = model.UserId
	}
}
