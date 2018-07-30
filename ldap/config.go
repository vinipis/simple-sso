package ldap

import (
	"crypto/rsa"
	"errors"
	"io/ioutil"
	"log"
	"os"
	"strconv"

	jwt "github.com/dgrijalva/jwt-go"

	"github.com/vinipis/simple-sso/sso"
)

// PrivateKey precisa de comentario
var PrivateKey *rsa.PrivateKey

//BaseConf precisa de comentario
var BaseConf *sso.BaseConfig

//Config precisa de comentario
type Config struct {
	host       string
	port       int
	ssl        bool
	basedn     string
	binddn     string
	bindPasswd string
}

func setupBaseConfig() {
	var err error
	BaseConf, err = sso.SetupBaseConfig()
	if err != nil {
		log.Fatal(err)
	}
	privateKeyData, err := ioutil.ReadFile(BaseConf.PrivateKeyPath)
	if err != nil {
		log.Fatal(err)
	}
	PrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(privateKeyData)
	if err != nil {
		log.Fatal(err)
	}
}

// setDefaultString returns a given default string.
func setDefaultString(s string, d string) string {
	if s == "" {
		return d
	}
	return s
}

// ldapConfig sets up ldap config from the env.
func (l *Config) setupLdapConfig() error {

	l.host = setDefaultString(os.Getenv(sso.ConfMap["sso_ldap_host"]), "localhost")

	port, err := strconv.Atoi(setDefaultString(os.Getenv(sso.ConfMap["sso_ldap_port"]), "389"))
	if err != nil {
		return err
	}
	l.port = port

	ssl, err := strconv.ParseBool(setDefaultString(os.Getenv(sso.ConfMap["sso_ldap_ssl"]), "false"))
	if err != nil {
		return err
	}
	l.ssl = ssl

	l.basedn = os.Getenv(sso.ConfMap["sso_ldap_basedn"])
	l.binddn = os.Getenv(sso.ConfMap["sso_ldap_binddn"])

	l.bindPasswd = os.Getenv(sso.ConfMap["sso_ldap_bindpasswd"])

	if l.binddn != "" && l.bindPasswd == "" {
		return errors.New("Bind dn is set but bind password is not set")
	}

	return nil
}
