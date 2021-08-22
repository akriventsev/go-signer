package gosigner

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"log"
	"testing"
)

type TestSignable struct {
}

func (ts TestSignable) SignString() string {
	return "TestStringToSign"
}

// GenerateKeyPair generates a new key pair
func generateKeyPair(bits int) (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privkey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, err
	}
	return privkey, &privkey.PublicKey, nil
}
func TestSha256Signer(t *testing.T) {
	// sign part
	privateKey, publicKey, err := generateKeyPair(1024)

	if err != nil {
		t.Fatalf("could not generate keypair: %s", err.Error())
	}
	privbytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Print(err)
		t.FailNow()
	}
	pemprivdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privbytes,
		},
	)

	pubbytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Print(err)
		t.FailNow()
	}
	pempubdata := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pubbytes,
		},
	)

	signer := Sha256Signer{}
	testSignable := TestSignable{}

	sign, err := signer.SignToBase64(testSignable, string(pemprivdata))
	if err != nil {
		log.Print(err)
		t.FailNow()
	}

	valid, err := signer.VerifyFromBase64(testSignable, sign, string(pempubdata))
	if err != nil {
		log.Print(err)
		t.FailNow()
	}
	if !valid {
		log.Print("validation incorrect")
		t.FailNow()
	}

}
