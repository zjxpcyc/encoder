package encoder

import (
	"errors"
	"fmt"
)

// 支持的加解密方式
const (
	MODE_BASE64     = "base64"
	MODE_MD5        = "md5"
	MODE_SHA1       = "sha1"
	MODE_SHA256     = "sha256"
	MODE_HMACSHA256 = "hmac-sha256"
	MODE_AESCBC     = "aes-cbc"
)

// Builder 构造加解密工具
type Builder struct {
	typ          string
	salt         string
	key          []byte
	iv           []byte
	blockPadding int
}

// NewBuilder 生成构造器
func NewBuilder(typ string) *Builder {
	return &Builder{
		typ:          typ,
		key:          make([]byte, 0),
		iv:           make([]byte, 0),
		blockPadding: 32,
	}
}

// Salt 加盐
func (b *Builder) Salt(salt string) *Builder {
	b.salt = salt
	return b
}

// Key 设置 key
func (b *Builder) Key(key []byte) *Builder {
	b.key = key
	return b
}

// IV 向量
func (b *Builder) IV(iv []byte) *Builder {
	b.iv = iv
	return b
}

// BlockPadding 块大小
func (b *Builder) BlockPadding(size int) *Builder {
	b.blockPadding = size
	return b
}

// Encrypt 加密
func (b *Builder) Encrypt(plaintext string) (string, error) {
	text := []byte(plaintext)

	switch b.typ {
	case MODE_BASE64:
		return Base64(text), nil
	case MODE_MD5:
		return MD5(text, b.salt), nil
	case MODE_SHA1:
		return SHA1(text), nil
	case MODE_SHA256:
		return SHA256(text), nil
	case MODE_HMACSHA256:
		return HmacSHA256(text, b.key), nil
	case MODE_AESCBC:
		result, err := AESCBCEncrypt(text, b.key, b.iv, b.blockPadding)
		if err != nil {
			return "", err
		}

		return fmt.Sprintf("%x", result), nil
	default:
		return "", errors.New("encrypt type not support")
	}
}

// Decrypt 解密
func (b *Builder) Decrypt(ciphertext string) ([]byte, error) {
	switch b.typ {
	case MODE_BASE64:
		return DeBase64(ciphertext)
	case MODE_AESCBC:
		return AESCBCDecrypt([]byte(ciphertext), b.key, b.iv)
	default:
		return nil, errors.New("decrypt type not support")
	}
}
