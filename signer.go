package gosigner

type SignerType int

const (
	SHA256 SignerType = iota
)

type Signable interface {
	SignString() string
}

type Signer interface {
	Sign(s Signable, privkey string) ([]byte, error)
	SignToBase64(s Signable, privkey string) (string, error)
	Verify(s Signable, sign []byte, pubkey string) (bool, error)
	VerifyFromBase64(s Signable, sign string, pubkey string) (bool, error)
}

func New(t SignerType) Signer {
	switch t {
	case SHA256:
		return Sha256Signer{}
	}
	return Sha256Signer{}
}
