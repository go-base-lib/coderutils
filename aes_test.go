package coderutils

import (
	"github.com/go-base-lib/goextension"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestAesEncryptAndDecrypt(t *testing.T) {
	a := assert.New(t)

	originData := []byte(GetRandomString(64))
	key := RandomAesKey(16)

	encrypt, err := AesCBCEncrypt(originData, key)
	if !a.NoError(err) {
		return
	}

	decrypt, err := AesCBCDecrypt(encrypt, key)
	if !a.NoError(err) {
		return
	}

	a.Equal(originData, decrypt.Raw())

}

func TestAesDecryptNodejsEncryptData(t *testing.T) {
	a := assert.New(t)

	nodejsEncryptData := goextension.Bytes("09e5f81dcd3b0817f77b94a42d469106")

	encBytes, err := nodejsEncryptData.DecodeHex()
	if !a.NoError(err) {
		return
	}

	encKey := goextension.Bytes("z5x4KrhJPk0OMzBkjigbtA==")
	k, err := encKey.DecodeBase64()
	if !a.NoError(err) {
		return
	}

	originData, err := AesCBCDecrypt(encBytes, k)
	if !a.NoError(err) {
		return
	}

	a.Equal(originData.ToString(), "12345")

}
