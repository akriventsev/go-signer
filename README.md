# go-signer
Module for sign objects

```go
type SignableObject struct {
    Id int
    Value string
}

func (o SignableObject) SignString() string {
	return fmt.Sprintf("MyObject_%d",id)
}

signer := gosigner.New(gosigner.SHA256)
object := SignableObject{
    Id: 22,
    Value: "object",
}

sign, err := signer.SignToBase64(ojbject, privkey)

valid, err := signer.VerifyFromBase64(testSignable, sign, pubkey)

```