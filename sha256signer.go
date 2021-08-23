package gosigner

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
)

type Sha256Signer struct {
}

func (signer Sha256Signer) Sign(s Signable, key string) ([]byte, error) {

	block, _ := pem.Decode([]byte(key))
	if block == nil {
		return nil, fmt.Errorf("invalid private Key")
	}

	privateKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("invalid Private Key")
	}

	digest := sha256.Sum256([]byte(s.SignString()))

	signature, signErr := rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA256, digest[:])

	if signErr != nil {
		return nil, fmt.Errorf("could not sign message:%s", signErr.Error())
	}
	return signature, nil
}

func (signer Sha256Signer) SignToBase64(s Signable, private_key string) (string, error) {
	signature, err := signer.Sign(s, private_key)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(signature), nil
}

func (signer Sha256Signer) Verify(s Signable, sign []byte, pubkey string) (bool, error) {
	block, _ := pem.Decode([]byte(pubkey))
	if block == nil {
		return false, fmt.Errorf("invalid public Key")
	}
	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return false, err
	}

	d := sha256.Sum256([]byte(s.SignString()))

	err = rsa.VerifyPKCS1v15(key.(*rsa.PublicKey), crypto.SHA256, d[:], sign)
	if err != nil {
		return false, nil
	}
	return true, nil
}

func (signer Sha256Signer) VerifyFromBase64(s Signable, sign string, pubkey string) (bool, error) {
	sig, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return false, err
	}
	return signer.Verify(s, sig, pubkey)
}
