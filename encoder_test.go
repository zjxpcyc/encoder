package encoder_test

import (
	"fmt"
	"testing"

	"github.com/zjxpcyc/encoder"
)

var plaintext = "yansenissohandsome"

func TestBase64(t *testing.T) {
	expect := "eWFuc2VuaXNzb2hhbmRzb21l"

	if expect != encoder.Base64([]byte(plaintext)) {
		t.Fatalf("Test Base64 fail")
	}
}

func TestMD5(t *testing.T) {
	expect := "2f0943124b2bf8cab4a6783401c2c4a4"

	if expect != encoder.MD5([]byte(plaintext)) {
		t.Fatalf("Test MD5 fail")
	}

	expect = "ba7a2c8e651e41b7aa86cb1953c99cd4"
	if expect != encoder.MD5([]byte(plaintext), "yeah!") {
		t.Fatalf("Test MD5 with salt fail")
	}
}

func TestSHA1(t *testing.T) {
	expect := "46550ececf6e3591b401edf4f422de45c6f686e2"

	if expect != encoder.SHA1([]byte(plaintext)) {
		t.Fatalf("Test SHA1 fail")
	}
}

func TestSHA256(t *testing.T) {
	expect := "e5c4db3029334063b2576307f0b7468ceb75bb331147a028ce18b989bb075db6"

	if expect != encoder.SHA256([]byte(plaintext)) {
		t.Fatalf("Test SHA256 fail")
	}
}

func TestHmacSHA256(t *testing.T) {
	expect := "d52532b1ac6467eaf2e5bde66c433d704dabc8933f97778ae4167ae5a4aadd41"

	if expect != encoder.HmacSHA256([]byte(plaintext), []byte("yeah!")) {
		t.Fatalf("Test HmacSHA256 fail")
	}
}

func TestAESCBCEncrypt(t *testing.T) {
	expect := "12326581662bc64538c1577f1e9b49b6a464e7a1631a1d3534c771dfd9b89230"

	result, err := encoder.AESCBCEncrypt([]byte(plaintext), []byte("0123456789ABCDEF"), []byte("0123456789ABCDEF"), 32)
	if err != nil {
		t.Fatalf("Test AESCBCEncrypt fail: %s", err.Error())
	}

	if fmt.Sprintf("%x", result) != expect {
		t.Fatalf("Test AESCBCEncrypt fail: %s", fmt.Sprintf("%x", result))
	}
}
