package coderutils

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/go-base-lib/goextension"
)

func PEM2RsaPrivateKey(pemStr string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("PEM格式解析失败")
	}

	return x509.ParsePKCS1PrivateKey(block.Bytes)
}

func PEM2RsaPublicKey(pemStr string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, fmt.Errorf("PEM格式解析失败")
	}
	return x509.ParsePKCS1PublicKey(block.Bytes)
}

func RsaEncrypt(originData []byte, publicKey *rsa.PublicKey) (goextension.Bytes, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, publicKey, originData)
}

func RsaDecrypt(encryptData []byte, privateKey *rsa.PrivateKey) (goextension.Bytes, error) {
	return rsa.DecryptPKCS1v15(rand.Reader, privateKey, encryptData)
}
