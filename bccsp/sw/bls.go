package sw

import (
	"github.com/hyperledger/fabric/bccsp"
)
type blsSigner struct {

}

func (*blsSigner) Sign(k bccsp.Key, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {

	return k.(*blsPrivateKey).privKey.Sign(digest)
}

type blsPrivateKeyVerifier struct {

}

func (*blsPrivateKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return k.(*blsPrivateKey).privKey.PubKey.Verify(signature,digest)
}

type blsPublicKeyVerifier struct {

}

func (*blsPublicKeyVerifier) Verify(k bccsp.Key, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	return k.(*blsPublicKey).pubKey.Verify(signature,digest)
}


