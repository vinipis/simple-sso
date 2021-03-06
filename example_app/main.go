package main

import (
	"crypto/rsa"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strings"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/vinipis/simple-sso/util"
)

var parsedPubKey *rsa.PublicKey

func init() {
	key, _ := ioutil.ReadFile(os.Getenv("HOME") + "/go/src/github.com/vinipis/simple-sso/key_pair/demo.rsa.pub") // esta é a chave pública do servidor de login (simple-sso)
	parsedPubKey, _ = jwt.ParseRSAPublicKeyFromPEM(key)
}

func cookieCheck(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie("SSO_C")
	if err == http.ErrNoCookie {
		// nós redirecionamos para o serviço de login definindo o s_url apropriado para retornar após a autenticação.
		http.Redirect(w, r, "https://127.0.0.1:8081/sso?s_url=https://127.0.0.1:8082/cookie", 301)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	parts := strings.Split(strings.Split(c.String(), "=")[1], ".")
	err = jwt.SigningMethodRS512.Verify(strings.Join(parts[0:2], "."), parts[2], parsedPubKey)
	if err != nil {
		log.Fatalf("[%v] Error while verifying key: %v", strings.Split(c.String(), "=")[1], err)
	}

	tokenString := strings.Split(c.String(), "=")[1]
	token, err := jwt.ParseWithClaims(tokenString, &util.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return parsedPubKey, nil
	})

	claims, ok := token.Claims.(*util.CustomClaims) // claims.User e claims.Roles são o que nos interessa.
	if ok && token.Valid {
		fmt.Printf("User: %v Roles: %v Tok_Expires: %v \n", claims.User, claims.Roles, claims.StandardClaims.ExpiresAt)

	} else {
		fmt.Println(err)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "You have visited a cookietest page.\n\n")
	fmt.Fprintf(w, "User: %v, Roles: %v, Tok_Expires: %v\n", claims.User, claims.Roles, claims.StandardClaims.ExpiresAt)
	return
}

func authTokCheck(w http.ResponseWriter, r *http.Request) {
	h := r.Header.Get("Authorization")
	if h == "" {
		http.Error(w, "No Authorization header", http.StatusInternalServerError)
		return
	}
	parts := strings.Split(strings.Split(h, " ")[1], ".")
	err := jwt.SigningMethodRS512.Verify(strings.Join(parts[0:2], "."), parts[2], parsedPubKey)
	if err != nil {
		log.Fatalf("[%v] Error while verifying key: %v", strings.Split(h, "=")[1], err)
	}

	tokenString := strings.Split(h, " ")[1]
	token, err := jwt.ParseWithClaims(tokenString, &util.CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return parsedPubKey, nil
	})

	claims, ok := token.Claims.(*util.CustomClaims) // claims.User e claims.Roles são o que nos interessa.
	if ok && token.Valid {
		fmt.Printf("User: %v Roles: %v Tok_Expires: %v \n", claims.User, claims.Roles, claims.StandardClaims.ExpiresAt)

	} else {
		fmt.Println(err)
	}
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "You have visited a auth tokentest page.\n\n")
	fmt.Fprintf(w, "User: %v, Roles: %v, Tok_Expires: %v\n", claims.User, claims.Roles, claims.StandardClaims.ExpiresAt)
	return
}
func main() {
	log.Println("Starting app server.")
	r := mux.NewRouter()
	r.HandleFunc("/cookie", cookieCheck)
	r.HandleFunc("/auth_token", authTokCheck)

	http.Handle("/", r)
	err := http.ListenAndServeTLS(":8082", os.Getenv("HOME")+"/go/src/github.com/vinipis/simple-sso/ssl_certs/cert.pem", os.Getenv("HOME")+"/go/src/github.com/vinipis/simple-sso/ssl_certs/key.pem", nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
