package encoder_test

import (
	"encoding/hex"
	"testing"

	"github.com/zjxpcyc/encoder"
)

func TestDeBase64(t *testing.T) {
	ciphertext := "eWFuc2VuaXNzb2hhbmRzb21l"

	text, err := encoder.DeBase64(ciphertext)
	if err != nil {
		t.Fatalf("Test DeBase64 fail: %s", err.Error())
	}

	if string(text) != plaintext {
		t.Fatalf("Test DeBase64 fail")
	}
}

func TestAESCBCDecrypt(t *testing.T) {
	ciphertext, _ := hex.DecodeString("12326581662bc64538c1577f1e9b49b6a464e7a1631a1d3534c771dfd9b89230")

	text, err := encoder.AESCBCDecrypt([]byte(ciphertext), []byte("0123456789ABCDEF"), []byte("0123456789ABCDEF"))
	if err != nil {
		t.Fatalf("Test AESCBCDecrypt fail: %s", err.Error())
	}

	if string(text) != plaintext {
		t.Fatalf("Test AESCBCDecrypt fail")
	}
}
