# Encoder 简单的加解密

![](https://img.shields.io/badge/golang-v0.0.2-blue.svg)

总结了下，常用的简单加解密(散列)方法


目前支持以下几种:

* Base64 加解密
* MD5 加密
* SHA1 加密
* SHA256 加密
* HMAC-SHA256 加密
* AES-CBC 加解密 (PCKS#5、PCKS#7)

## 安装
```bash
// x.y.z 为版本号
go get github.com/zjxpcyc/encoder@vx.y.z
```

## 使用
使用方式有两种, 一种是自由组合的，任意使用的。另外一种是使用 Builder

**加密列表**
```golang
func Base64(plaintext []byte) string

func MD5(plaintext []byte, salt ...string) string

func SHA1(plaintext []byte) string

func SHA256(plaintext []byte) string

func HmacSHA256(plaintext, key []byte) string

func AESCBCEncrypt(plaintext, key, iv []byte, pkcsPadding ...int) ([]byte, error)
```

**解密列表**
```golang
func DeBase64(ciphertext string) ([]byte, error)

func AESCBCDecrypt(ciphertext, key, iv []byte) ([]byte, error)
```

**Builder**

请查阅 builder 文件


**示例**
```golang
// md5 加密 - 简单方式
result := encoder.MD5("a plain text") // dst := encoder.MD5("a plain text", " salt string ")

// Hmac-SHA256 builder 方式
result, err := encoder.NewBuilder(encoder.MODE_HMACSHA256).key("HMAC key here").Encrypt("a plain text")
```

