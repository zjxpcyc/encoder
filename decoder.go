package encoder

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
)

// DeBase64 解密
func DeBase64(ciphertext string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(ciphertext)
}

// AESCBCDecrypt 解密
// ciphertext 密文
func AESCBCDecrypt(ciphertext, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// 使用拷贝数据, 目的是不改变 ciphertext
	text := ciphertext

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(text, text)

	// 如果需要拿到字符串, 请使用
	// fmt.Sprintf("%s", PKCUnPadding(text))
	return PKCSUnPadding(text), nil
}

// PKCSUnPadding 取消填充
func PKCSUnPadding(dt []byte) []byte {
	length := len(dt)

	unpadding := int(dt[length-1])
	return dt[:(length - unpadding)]
}
