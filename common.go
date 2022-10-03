package coderutils

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"fmt"
	"github.com/go-base-lib/goextension"
)

type AesKeyLen int

const (
	AesKeyLen16 AesKeyLen = 16
	AesKeyLen32 AesKeyLen = 32
	AesKeyLen64 AesKeyLen = 64
)

func RandomAesKey(keyLen AesKeyLen) goextension.Bytes {
	l := int(keyLen)
	return []byte(GetRandomString(l))[:l]
}

// PKCS7Padding PKCS#7格式填充
func PKCS7Padding(ciphertext []byte, blockSize int) goextension.Bytes {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

// PKCS7UnPadding PKCS#7格式去除填充
func PKCS7UnPadding(origData []byte) goextension.Bytes {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

// AesCBCEncrypt aes加密，填充秘钥key的16位，24,32分别对应AES-128, AES-192, or AES-256.
func AesCBCEncrypt(rawData, key []byte) (goextension.Bytes, error) {
	keyLen := len(key)
	if keyLen%16 != 0 || keyLen < int(AesKeyLen16) || keyLen > int(AesKeyLen64) {
		return nil, fmt.Errorf("密钥长度不正确")
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	//填充原文
	blockSize := block.BlockSize()
	rawData = PKCS7Padding(rawData, blockSize)
	//初始向量IV必须是唯一，但不需要保密
	cipherText := make([]byte, len(rawData))
	//block大小 16
	iv := key
	//block大小和初始向量大小一定要一致
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(cipherText, rawData)

	return cipherText, nil
}

// AesCBCDecrypt aes cbc模式解密
func AesCBCDecrypt(encryptData, key []byte) (goextension.Bytes, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}

	blockSize := block.BlockSize()

	if len(encryptData) < blockSize {
		return nil, errors.New("ciphertext too short")
	}
	iv := key

	// CBC mode always works in whole blocks.
	if len(encryptData)%blockSize != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}

	mode := cipher.NewCBCDecrypter(block, iv)

	// CryptBlocks can work in-place if the two arguments are the same.
	mode.CryptBlocks(encryptData, encryptData)
	//解填充
	encryptData = PKCS7UnPadding(encryptData)
	return encryptData, nil
}
