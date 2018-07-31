package util

import (
	"crypto/rsa"

	jwt "github.com/dgrijalva/jwt-go"
)

//CustomClaims todo objeto precisa ser comentado
type CustomClaims struct {
	User  string   `json:"user"`
	Roles []string `json:"roles"`
	jwt.StandardClaims
}

// GenJWT gera o token jwt. Entre outras coisas, ele embala o nome de usuário autenticado e os papéis que
// o usuário pertence e um tempo de expiração. A informação é então assinada pela chave privada do servidor de login.
func GenJWT(u string, g []string, p *rsa.PrivateKey, t int64) (string, error) {
	claims := CustomClaims{
		u,
		g,
		jwt.StandardClaims{
			ExpiresAt: t,
			Issuer:    "Login_Server",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS512, claims)
	return token.SignedString(p)
}
