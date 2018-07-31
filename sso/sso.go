package sso

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"time"
)

var (
	//ErrUnAuthorized precisa ser comentado por ser um objeto
	ErrUnAuthorized = errors.New("Não autorizado")
	//ErrUserNotFound precisa ser comentado por ser um objeto
	ErrUserNotFound = errors.New("Usuário não encontrado")
)

// SSOer é o que precisa ser implementado para a funcionalidade sso.
type SSOer interface {
	// Auth leva o usuário, as strings de senha como argumentos e retorna o usuário, funções de usuário (por exemplo, grupos de ldap)
	// (fatia de string) se a chamada é processada. A autenticação deve retornar o erro ErrUnAuthorized ou ErrUserNotFound se
	// auth falha ou se o usuário não for encontrado respectivamente.
	Auth(string, string) (*string, *[]string, error)
	// CTValidHours retorna a validade do token de cookie/jwt em horas.
	CTValidHours() int64
	CookieName() string
	CookieDomain() string
	// BuildJWTToken leva o usuário e as informações de papéis do usuário que são assinadas pelo private
	// chave do servidor de login. A expiração do token é definida pelo terceiro argumento.
	BuildJWTToken(string, []string, time.Time) (string, error)
	// BuildCookie pega o token jwt e retorna um cookie e configura o tempo de expiração do mesmo para o de
	// o segundo arg.
	BuildCookie(string, time.Time) http.Cookie
	// Logout define o tempo de expiração do cookie no passado tornando-o inutilizável.
	Logout(time.Time) http.Cookie
}

//Err401Map precisa ser comentado
var Err401Map = map[error]bool{
	ErrUnAuthorized: true,
	ErrUserNotFound: true,
}

//ConfMap Todas as variáveis de ambiente config vão aqui para melhor rastreamento.
var ConfMap = map[string]string{
	// ssl certs.
	"sso_ssl_cert_path": "sso_ssl_cert_path",
	"sso_ssl_key_path":  "sso_ssl_key_path",
	// caminho da chave privada para assinar o jwt.
	"sso_private_key_path": "sso_private_key_path",
	// caminho do diretório do weblog
	"sso_weblog_dir": "sso_weblog_dir",
	// Funções do usuário para autorização, (true/false)
	"sso_user_roles": "sso_user_roles",
	// configurações de cookies.
	"sso_cookie_name":       "sso_cookie_name",
	"sso_cookie_domain":     "sso_cookie_domain",
	"sso_cookie_validhours": "sso_cookie_validhours",
	// ldap configs. Isso deve ir para o respectivo pacote.
	"sso_ldap_host":       "sso_ldap_host",
	"sso_ldap_port":       "sso_ldap_port",
	"sso_ldap_ssl":        "sso_ldap_ssl",
	"sso_ldap_basedn":     "sso_ldap_basedn",
	"sso_ldap_binddn":     "sso_ldap_binddn",
	"sso_ldap_bindpasswd": "sso_ldap_bindpasswd",
}

// setDefaultString retorna uma determinada string padrão.
func setDefaultString(s string, d string) string {
	if s == "" {
		return d
	}
	return s
}

//BaseConfig precisa de comentario
type BaseConfig struct {
	SSLCertPath    string
	SSLKeyPath     string
	PrivateKeyPath string
	WeblogDir      string
	UserRoles      bool
}

// SetupBaseConfig função configura algumas configurações genéricas
func SetupBaseConfig() (*BaseConfig, error) {
	sslCertPath := setDefaultString(os.Getenv(ConfMap["sso_ssl_cert_path"]), "/home/carlos/go/src/github.com/vinipis/simple-sso/ssl_certs/cert.pem")
	sslKeyPath := setDefaultString(os.Getenv(ConfMap["sso_ssl_key_path"]), "/home/carlos/go/src/github.com/vinipis/simple-sso/ssl_certs/key.pem")
	privateKeyPath := setDefaultString(os.Getenv(ConfMap["sso_private_key_path"]), "/home/carlos/go/src/github.com/vinipis/simple-sso/key_pair/demo.rsa")
	weblogDir := setDefaultString(os.Getenv(ConfMap["sso_weblog_dir"]), "")
	userRoles, err := strconv.ParseBool(setDefaultString(os.Getenv(ConfMap["sso_user_roles"]), "false"))
	if err != nil {
		return nil, err
	}
	return &BaseConfig{sslCertPath, sslKeyPath, privateKeyPath, weblogDir, userRoles}, nil
}

//CookieConfig precisa de comentario
type CookieConfig struct {
	Name       string
	Domain     string
	ValidHours int64
}

// SetupCookieConfig configura a configuração do cookie.
func SetupCookieConfig() (*CookieConfig, error) {
	name := setDefaultString(os.Getenv(ConfMap["sso_cookie_name"]), "SSO_C")
	domain := setDefaultString(os.Getenv(ConfMap["sso_cookie_domain"]), "127.0.0.1")
	validHours, err := strconv.Atoi(setDefaultString(os.Getenv(ConfMap["sso_cookie_validhours"]), "20"))
	if err != nil {
		return nil, err
	}
	return &CookieConfig{name, domain, int64(validHours)}, nil
}
