// SPDX-License-Identifier: MPL-2.0
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package crypto

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

// PrivateKeyToPKCS8PEM converts an EC private key emitted by the certificate
// issuer to unencrypted PKCS#8 PEM. Some TLS consumers (notably Kafka's JVM
// tooling) require the generic PKCS#8 container rather than SEC1. Keeping this
// conversion here preserves the rule that key serialization is owned by the
// crypto boundary.
func PrivateKeyToPKCS8PEM(keyPEM []byte) ([]byte, error) {
	block, rest := pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("crypto: private key PEM malformed")
	}
	if len(rest) != 0 {
		return nil, errors.New("crypto: private key PEM contains trailing data")
	}
	if block.Type != "EC PRIVATE KEY" {
		return nil, fmt.Errorf("crypto: expected EC PRIVATE KEY, got %q", block.Type)
	}
	key, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("crypto: parse EC private key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal PKCS#8 private key: %w", err)
	}
	return pemEncode("PRIVATE KEY", der), nil
}
