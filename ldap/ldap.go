// Package ldap é uma implementação sso. Ele usa um backend ldap para autenticar e opcionalmente
// utilizar membros do grupo ldap para configurar funções no cookie/jwt que podem ser usadas posteriormente
// por pedidos de autorização.
package ldap

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"gopkg.in/ldap.v2"

	"github.com/vinipis/simple-sso/sso"
	"github.com/vinipis/simple-sso/util"
)

//SSO precisa de comentario
type SSO struct {
	Cookie *sso.CookieConfig
	Ldap   *Config
}

//ErrUserNotFound deve ser comentado
var (
	ErrUserNotFound = sso.ErrUserNotFound
	ErrUnauthorized = sso.ErrUnAuthorized
)

//NewLdapSSO deve ser comentado
func NewLdapSSO() (*SSO, error) {
	setupBaseConfig()
	c, err := sso.SetupCookieConfig()
	if err != nil {
		return nil, err
	}

	l := new(Config)
	err = l.setupLdapConfig()
	if err != nil {
		return nil, err
	}

	return &SSO{c, l}, nil
}

//Auth precisa de comentario
func (ls SSO) Auth(u string, p string) (*string, *[]string, error) {

	ldap.DefaultTimeout = 20 * time.Second // aplica-se aos métodos Dial e DialTLS.
	l, err := ldap.Dial("tcp", fmt.Sprintf("%s:%d", ls.Ldap.host, ls.Ldap.port))
	if err != nil {
		return nil, nil, err
	}
	defer l.Close()

	// Reconecte-se com o TLS se o sso_ldap_ssl env estiver configurado.
	if ls.Ldap.ssl {
		err = l.StartTLS(&tls.Config{InsecureSkipVerify: true})
		if err != nil {
			return nil, nil, err
		}
	}

	// Primeira ligação com um usuário somente de leitura
	if ls.Ldap.binddn != "" {
		err = l.Bind(ls.Ldap.binddn, ls.Ldap.bindPasswd)
		if err != nil {
			return nil, nil, err
		}
	}

	// Procure pelo nome de usuário fornecido
	searchRequestUser := ldap.NewSearchRequest(
		ls.Ldap.basedn,
		ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, // define um limite de tempo de 30 segundos
		fmt.Sprintf("(&(objectClass=inetOrgPerson)(uid=%s))", u),
		[]string{"dn"},
		nil,
	)

	sru, err := l.Search(searchRequestUser)
	if err != nil {
		return nil, nil, err
	}

	if len(sru.Entries) != 1 {
		return nil, nil, ErrUserNotFound
	}

	userdn := sru.Entries[0].DN

	// Ligue como o usuário para verificar sua senha
	err = l.Bind(userdn, p)
	if err != nil {
		return nil, nil, ErrUnauthorized
	}

	// Agora, encontre a associação ao grupo (se sso_user_roles env for true).
	var g []string
	if BaseConf.UserRoles {
		searchRequestGroups := ldap.NewSearchRequest(
			ls.Ldap.basedn,
			ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 30, false, // define um limite de tempo de 30 segundos
			fmt.Sprintf("(&(objectClass=posixGroup)(memberUid=%s))", u),
			[]string{"cn"},
			nil,
		)
		srg, err := l.Search(searchRequestGroups)
		if err != nil {
			return &u, nil, err
		}

		g = srg.Entries[0].GetAttributeValues("cn")
	}

	return &u, &g, nil
}

//CTValidHours precisa de comentario
func (ls SSO) CTValidHours() int64 {
	return ls.Cookie.ValidHours
}

//BuildJWTToken precisa de comentario
func (ls SSO) BuildJWTToken(u string, g []string, exp time.Time) (string, error) {
	return util.GenJWT(u, g, PrivateKey, exp.Unix())

}

// CookieName precisa de comentario
func (ls SSO) CookieName() string {
	return ls.Cookie.Name
}

// CookieDomain precisa de comentario
func (ls SSO) CookieDomain() string {
	return ls.Cookie.Domain
}

// BuildCookie precisa de comentario
func (ls SSO) BuildCookie(s string, exp time.Time) http.Cookie {
	c := http.Cookie{
		Name:     ls.Cookie.Name,
		Value:    s,
		Domain:   ls.Cookie.Domain,
		Path:     "/",
		Expires:  exp,
		MaxAge:   int(ls.Cookie.ValidHours * 3600),
		Secure:   true,
		HttpOnly: true,
	}
	return c
}

// Logout precisa de comentario
func (ls SSO) Logout(expT time.Time) http.Cookie {
	c := http.Cookie{
		Name:     ls.Cookie.Name,
		Value:    "",
		Domain:   ls.Cookie.Domain,
		Path:     "/",
		Expires:  expT,
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
	}
	return c
}
