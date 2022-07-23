package coderutils

import (
	cryptoRand "crypto/rand"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"github.com/tjfoc/gmsm/x509"
	"math/rand"
	"time"
)

// GetRandomString 获取指定长度的随机字符串
func GetRandomString(l int) string {
	str := "0123456789abcdefghijklmnopqrstuvwxyz~！@#￥%……&*（）——+」|「P:>?/*-+.+*_*+我爱中国^_^"
	//str := "0123456789abcdefghijklmnopqrstuvwxyz"
	bytes := []rune(str)
	result := make([]rune, l, l)
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	for i := 0; i < l; i++ {
		result[i] = bytes[r.Intn(len(bytes))]
		//result = append(result, bytes[r.Intn(len(bytes))])
	}
	return string(result)
}

func ConvertPemToPrivateKey(privateKeyPem string) (*sm2.PrivateKey, error) {
	block, _ := pem.Decode([]byte(privateKeyPem))
	if block == nil {
		return nil, errors.New("解析私钥信息失败")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes, nil)
	if err != nil {
		return nil, errors.New("转换私钥信息失败")
	}

	return key, nil
}

func ConvertPemToPublicKey(pubPem string) (*sm2.PublicKey, error) {
	block, _ := pem.Decode([]byte(pubPem))
	if block == nil {
		return nil, errors.New("解析公钥信息失败")
	}
	key, err := x509.ParseSm2PublicKey(block.Bytes)
	if err != nil {
		return nil, errors.New("转换公钥信息失败")
	}

	return key, nil
}

func ConvertPemToPubAndPriKey(pubKeyPem, privateKeyPem string) (*sm2.PublicKey, *sm2.PrivateKey, error) {
	pubKey, err := ConvertPemToPublicKey(pubKeyPem)
	if err != nil {
		return nil, nil, err
	}

	privateKey, err := ConvertPemToPrivateKey(privateKeyPem)
	if err != nil {
		return nil, nil, err
	}

	return pubKey, privateKey, nil
}

// Sm4Encrypt sm4加密
func Sm4Encrypt(key, plainText []byte) ([]byte, error) {
	return sm4.Sm4Ecb(key, plainText, true)
}

// Sm4Decrypt sm4解密
func Sm4Decrypt(key, cipherText []byte) ([]byte, error) {
	return sm4.Sm4Ecb(key, cipherText, false)
}

// Sm4RandomKey Sm4随机ke
func Sm4RandomKey() []byte {
	return []byte(GetRandomString(16))[:16]
}

func Sm2KeyEncryptWithMod(pubKey *sm2.PublicKey, data []byte, mod int) ([]byte, error) {
	encrypt, err := sm2.Encrypt(pubKey, data, cryptoRand.Reader, mod)
	if err != nil {
		return nil, errors.New("加密数据失败")
	}
	return encrypt, err
}

// Sm2Encrypt Sm2加密
func Sm2Encrypt(pemPublicKey string, data []byte) ([]byte, error) {
	key, err := ConvertPemToPublicKey(pemPublicKey)
	if err != nil {
		return nil, err
	}
	return Sm2KeyEncryptWithMod(key, data, sm2.C1C2C3)
}

func Sm2EncryptWithMod(pemPublicKey string, data []byte, mod int) ([]byte, error) {
	key, err := ConvertPemToPublicKey(pemPublicKey)
	if err != nil {
		return nil, err
	}

	return Sm2KeyEncryptWithMod(key, data, mod)
}

func Sm2KeyDecryptWithMod(priKey *sm2.PrivateKey, data []byte, mod int) ([]byte, error) {
	decrypt, err := sm2.Decrypt(priKey, data, mod)
	if err != nil {
		return nil, errors.New("解密数据失败")
	}
	return decrypt, nil
}

func Sm2DecryptWithMod(pemPrivateKey string, data []byte, mod int) ([]byte, error) {
	key, err := ConvertPemToPrivateKey(pemPrivateKey)
	if err != nil {
		return nil, err
	}
	return Sm2KeyDecryptWithMod(key, data, mod)
}

// Sm2Decrypt sn2解密
func Sm2Decrypt(pemPrivateKey string, data []byte) ([]byte, error) {
	key, err := ConvertPemToPrivateKey(pemPrivateKey)
	if err != nil {
		return nil, err
	}

	return Sm2KeyDecryptWithMod(key, data, sm2.C1C3C2)
}

func Sm2Sign(pemPrivateKey string, data []byte) ([]byte, error) {
	key, err := ConvertPemToPrivateKey(pemPrivateKey)
	if err != nil {
		return nil, err
	}

	return Sm2SignWithKey(key, data)
}

func Sm2VerifySign(pemPubKey string, sign, data []byte) (bool, error) {
	key, err := ConvertPemToPublicKey(pemPubKey)
	if err != nil {
		return false, err
	}
	return Sm2VerifySignWithKey(key, sign, data), nil
}

func Sm2VerifySignWithKey(publicKey *sm2.PublicKey, sign, data []byte) bool {
	return publicKey.Verify(sign, data)
}

func Sm2SignWithKey(privateKey *sm2.PrivateKey, data []byte) ([]byte, error) {
	return privateKey.Sign(cryptoRand.Reader, data, nil)
}

// Sm2DecryptByBase64Data sm2解密，数据格式为Base64
func Sm2DecryptByBase64Data(pemPrivateKey string, data string) ([]byte, error) {
	d, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return nil, errors.New("解析数据失败")
	}
	return Sm2Decrypt(pemPrivateKey, d)
}
