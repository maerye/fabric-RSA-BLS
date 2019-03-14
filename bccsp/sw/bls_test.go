package sw

import (
	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bls"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestBLSSignerSign(t *testing.T)  {
	t.Parallel()

	signer := &blsSigner{}
	verifierPrivateKey := &blsPrivateKeyVerifier{}
	verifierPublicKey := &blsPublicKeyVerifier{}

	// Generate a key
	kg := blsKeyGenerator{}
	k, err := kg.KeyGen(&bccsp.BLSKeyGenOpts{true})
	assert.NoError(t, err)
	kb,_:=k.Bytes()
	kn,_:=bls.PriKeyFromBytes(kb)
	kpub,_:=k.PublicKey()
	kpubb,_ := kpub.Bytes()
	kp,_ :=bls.PubKeyFromBytes(kpubb)

	assert.NotNil(t,kn)

	pk, err := k.PublicKey()
	assert.NoError(t, err)
	// Sign
	msg := []byte("Hello World")
	sigma, err := signer.Sign(k, msg, nil)
	assert.NoError(t, err)
	assert.NotNil(t, sigma)

	sigma2, err :=kn.Sign(msg)
	is,err:=kp.Verify(sigma2,msg)
	assert.True(t,is)
	assert.NoError(t, err)
	assert.NotNil(t, sigma2)

	assert.EqualValues(t,sigma,sigma2)
	// Verify


	valid, err := verifierPrivateKey.Verify(k, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPublicKey.Verify(pk, sigma, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)

	valid, err = verifierPrivateKey.Verify(k, sigma2, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)


	valid, err = verifierPublicKey.Verify(pk, sigma2, msg, nil)
	assert.NoError(t, err)
	assert.True(t, valid)
}