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

func (csp *impl) signECDSA(k ecdsaPrivateKey, digest []byte, opts bccsp.SignerOpts) (signature []byte, err error) {
	pub, err := k.PublicKey()
	if err != nil {
		panic(nil)
	}

	data, err := pub.Bytes()
	if err != nil {
		panic(nil)
	}

	return hellgost.GetClient().Sign(string(data), digest)
}

func (csp *impl) verifyECDSA(k ecdsaPublicKey, signature, digest []byte, opts bccsp.SignerOpts) (valid bool, err error) {
	pub, err := k.PublicKey()
	if err != nil {
		panic(nil)
	}

	data, err := pub.Bytes()
	if err != nil {
		panic(nil)
	}
	return hellgost.GetClient().Verify(string(data), digest, signature)
}
