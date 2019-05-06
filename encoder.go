package encoder

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// Base64 加密
func Base64(plaintext []byte) string {
	return base64.StdEncoding.EncodeToString(plaintext)
}

// MD5 加密
func MD5(plaintext []byte, salt ...string) string {
	text := dup(plaintext)

	if len(salt) > 0 && salt[0] != "" {
		for _, s := range salt {
			text = append(text, []byte(s)...)
		}
	}

	return fmt.Sprintf("%x", md5.Sum(text))
}

// SHA1 加密
func SHA1(plaintext []byte) string {
	return fmt.Sprintf("%x", sha1.Sum(plaintext))
}

// SHA256 加密
func SHA256(plaintext []byte) string {
	return fmt.Sprintf("%x", sha256.Sum256(plaintext))
}

// HmacSHA256 加密
func HmacSHA256(plaintext, key []byte) string {
	h := hmac.New(sha256.New, key)
	h.Write(plaintext)
	return fmt.Sprintf("%x", h.Sum(nil))
}

// AESCBCEncrypt 加密
// plaintext 明文
// pkcsPadding 0 不做填充操作, > 1  pcks#7填充
func AESCBCEncrypt(plaintext, key, iv []byte, pkcsPadding ...int) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 计算填充内容长度, 理论上 pkcs#7 支持 1-255 的任意长度填充
	// 但是 AES 的块大小是 16 byte, 因此, 非 16 倍数的长度实际上是不支持的
	psLen := block.BlockSize()
	if len(pkcsPadding) > 0 && pkcsPadding[0] > 0 {
		psLen = pkcsPadding[0]
	}

	ciphertext := PKCS7Padding(plaintext, psLen)

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, ciphertext)

	// 如果需要拿到字符串, 请使用
	// fmt.Sprintf("%x", ciphertext)
	// 或者使用 base64 转码
	return ciphertext, nil
}

// PKCS7Padding pkcs#7 的填充算法
// 注: pkcs#5 不适用 AES 算法。但是本函数，也可以当做 pkcs#5 使用
// https://tools.ietf.org/html/rfc2315
func PKCS7Padding(plaintext []byte, blockSize int) []byte {
	padding := blockSize - len(plaintext)%blockSize
	if padding == 0 {
		padding = blockSize
	}

	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(plaintext, padtext...)
}

func dup(s []byte) []byte {
	t := make([]byte, len(s))
	copy(t, s)
	return t
}
