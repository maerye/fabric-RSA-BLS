package sw

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bls"
)


type blsPrivateKey struct {
	privKey *bls.PrivateKey
}

func (k *blsPrivateKey) Bytes() ([]byte, error) {


	return k.privKey.Bytes()
}

func (k *blsPrivateKey) SKI() []byte {
	if k.privKey == nil {
		return nil
	}

	raw,_:= k.privKey.PubKey.Bytes()

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}


func (*blsPrivateKey) Symmetric() bool {
	return false
}

func (*blsPrivateKey) Private() bool {
	return true
}

func (k *blsPrivateKey) PublicKey() (bccsp.Key, error) {
	return &blsPublicKey{k.privKey.PubKey},nil
}


type blsPublicKey struct {
	pubKey *bls.PublicKey
}

func (k *blsPublicKey) Bytes() (raw []byte, err error) {
	if k.pubKey == nil {
		return nil, errors.New("Failed marshalling key. Key is nil.")
	}
	raw,_ = k.pubKey.Bytes()
	if len(raw) ==0 {
		return nil, fmt.Errorf("Failed generate bls bytes key [%s]", err)
	}
	return

}

func (k *blsPublicKey) SKI() []byte {
	if k.pubKey == nil {
		return nil
	}

	// Marshall the public key
	raw,_:= k.pubKey.Bytes()

	// Hash it
	hash := sha256.New()
	hash.Write(raw)
	return hash.Sum(nil)
}

func (*blsPublicKey) Symmetric() bool {
	return false
}

func (*blsPublicKey) Private() bool {
	return false
}

func (k *blsPublicKey) PublicKey() (bccsp.Key, error) {
	return k,nil
}

