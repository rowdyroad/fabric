/*
Copyright IBM Corp. 2016 All Rights Reserved.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

		 http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
package pkcs11

import (
	"crypto/elliptic"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/hyperledger/fabric/bccsp"
	"github.com/hyperledger/fabric/bccsp/hellgost"
)

var (
	// curveHalfOrders contains the precomputed curve group orders halved.
	// It is used to ensure that signature' S value is lower or equal to the
	// curve group order halved. We accept only low-S signatures.
	// They are precomputed for efficiency reasons.
	curveHalfOrders map[elliptic.Curve]*big.Int = map[elliptic.Curve]*big.Int{
		elliptic.P224(): new(big.Int).Rsh(elliptic.P224().Params().N, 1),
		elliptic.P256(): new(big.Int).Rsh(elliptic.P256().Params().N, 1),
		elliptic.P384(): new(big.Int).Rsh(elliptic.P384().Params().N, 1),
		elliptic.P521(): new(big.Int).Rsh(elliptic.P521().Params().N, 1),
	}
)

type ECDSASignature struct {
	R, S *big.Int
}

func MarshalECDSASignature(r, s *big.Int) ([]byte, error) {
	return asn1.Marshal(ECDSASignature{r, s})
}

func UnmarshalECDSASignature(raw []byte) (*big.Int, *big.Int, error) {
	// Unmarshal
	sig := new(ECDSASignature)
	_, err := asn1.Unmarshal(raw, sig)
	if err != nil {
		return nil, nil, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}
	return sig.R, sig.S, nil
}

func (csp *impl) signECDSA(k ecdsaPrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	pub, err := k.PublicKey()
	if err != nil {
		panic(nil)
	}

	data, err := pub.Bytes()
	if err != nil {
		panic(nil)
	}
	sign, err := hellgost.GetClient().Sign(hex.EncodeToString(data), digest)
	if err != nil {
		panic(nil)
	}
	r := new(big.Int)
	r.SetBytes(sign)
	s := big.NewInt(1)
	return MarshalECDSASignature(r, s)
}

func (csp *impl) verifyECDSA(k ecdsaPublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	r, _, err := UnmarshalECDSASignature(signature)
	if err != nil {
		return false, fmt.Errorf("Failed unmashalling signature [%s]", err)
	}

	pub, err := k.PublicKey()
	if err != nil {
		panic(nil)
	}

	data, err := pub.Bytes()
	if err != nil {
		panic(nil)
	}
	return hellgost.GetClient().Verify(hex.EncodeToString(data), digest, r.Bytes())
}
