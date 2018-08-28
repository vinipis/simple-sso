package main

//go:generate go-bindata templates/...

import (
	"fmt"
	"html/template"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	weblog "github.com/vinipis/goProbe/log"

	"github.com/vinipis/simple-sso/ldap"
	"github.com/vinipis/simple-sso/sso"
)

var lsso sso.SSOer
var templates = template.New("")

func init() {
	var err error
	lsso, err = ldap.NewLdapSSO()
	if err != nil {
		log.Fatalf("Erro ao inicializar o ldap sso: %s", err)
	}

	for _, path := range AssetNames() {
		bytes, err := Asset(path)
		if err != nil {
			log.Fatalf("Não é possível analisar: caminho=%s, err=%s", path, err)
		}
		templates.New(path).Parse(string(bytes))
	}
}

// TmplData precisa ser comentado
type TmplData struct {
	QueryString string
	Error       bool
}

func renderTemplate(w http.ResponseWriter, tmpl string, p interface{}) {
	err := templates.ExecuteTemplate(w, tmpl, p)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// handleSSOGetRequest apresenta o formulário de login
func handleSSOGetRequest(w http.ResponseWriter, r *http.Request) {
	err := false
	if r.URL.Query().Get("auth_error") != "" {
		err = true
	}
	tmplData := TmplData{QueryString: r.URL.Query().Get("s_url"), Error: err}
	renderTemplate(w, os.Getenv("HOME")+"/go/src/github.com/vinipis/simple-sso/templates/login.html", &tmplData)
}

// handleSSOPostRequest define o cookie sso.
func handleSSOPostRequest(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	pURI := r.PostFormValue("query_string")

	u, g, err := lsso.Auth(r.PostFormValue("username"), r.PostFormValue("password"))
	if u != nil {
		vh := lsso.CTValidHours()
		exp := time.Now().Add(time.Hour * time.Duration(vh)).UTC()
		tok, _ := lsso.BuildJWTToken(*u, *g, exp)
		c := lsso.BuildCookie(tok, exp)
		http.SetCookie(w, &c)
		http.Redirect(w, r, pURI, 301)
		return
	}
	if err != nil {
		if sso.Err401Map[err] {
			log.Println(err)
			http.Redirect(w, r, fmt.Sprintf("/sso?s_url=%s&auth_error=true", pURI), 301)
			return
		}
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Não é possível atender a essa solicitação. Por favor, tente novamente mais tarde.")
		return

	}
}

// handleAuthTokenRequest gera o token jwt bruto e o envia.
func handleAuthTokenRequest(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	u, g, err := lsso.Auth(r.PostFormValue("username"), r.PostFormValue("password"))
	if u != nil {
		tok, _ := lsso.BuildJWTToken(*u, *g, time.Now().Add(time.Hour*time.Duration(lsso.CTValidHours())).UTC())
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, tok)
		return
	}
	if err != nil {
		if sso.Err401Map[err] {
			log.Println(err)
			fmt.Fprintf(w, "Não autorizado.")
			return
		}
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, "Não é possível atender o pedido. Por favor, tente novamente mais tarde.")
		return

	}
}

// handleLogoutRequest função invalida o cookie sso.
func handleLogoutRequest(w http.ResponseWriter, r *http.Request) {
	expT := time.Now().Add(time.Hour * time.Duration(-1))
	lc := lsso.Logout(expT)

	http.SetCookie(w, &lc)
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Você foi desconectado.")
	return
}

// handleTestRequest função é apenas para fins de teste.
func handleTestRequest(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	fmt.Fprintf(w, "Você visitou uma página de teste.")
	return
}

func main() {
	log.Println("Iniciando o servidor de login.")
	r := mux.NewRouter()

	var fh *os.File
	var err error
	wld := ldap.BaseConf.WeblogDir
	if wld != "" {
		fh, err = weblog.SetupWebLog(wld, time.Now())
		if err != nil {
			log.Fatalf("Falha ao configurar o registro: %v", err)
		}
	} else {
		fh = os.Stdout // registra os acessos da web ao stdout. Pode não ser thread safe.
	}

	r.Handle("/sso", handlers.CombinedLoggingHandler(fh, http.HandlerFunc(handleSSOPostRequest))).Methods("POST")
	r.Handle("/sso", handlers.CombinedLoggingHandler(fh, http.HandlerFunc(handleSSOGetRequest))).Methods("GET")
	r.Handle("/logout", handlers.CombinedLoggingHandler(fh, http.HandlerFunc(handleLogoutRequest))).Methods("GET")
	r.Handle("/auth_token", handlers.CombinedLoggingHandler(fh, http.HandlerFunc(handleAuthTokenRequest))).Methods("POST")
	r.Handle("/test", handlers.CombinedLoggingHandler(fh, http.HandlerFunc(handleTestRequest))).Methods("GET")

	http.Handle("/", r)

	err = http.ListenAndServeTLS(":8081", ldap.BaseConf.SSLCertPath, ldap.BaseConf.SSLKeyPath, nil)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
