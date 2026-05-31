package crypto

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
)

// KeyProvider supplies the Key Encryption Key (KEK) that wraps per-record data
// keys. In production this is a KMS/HSM; locally it is a static dev key.
// Per-tenant KEKs and BYOK/HYOK are F56 (Phase 2 / EE).
type KeyProvider interface {
	// KeyID identifies the active KEK; it is stored with each sealed value for
	// rotation and audit.
	KeyID() string
	// WrapKey encrypts (wraps) a data key.
	WrapKey(ctx context.Context, dek []byte) ([]byte, error)
	// UnwrapKey decrypts a wrapped data key.
	UnwrapKey(ctx context.Context, wrapped []byte) ([]byte, error)
}

// StaticKeyProvider wraps data keys with a single static KEK. It is for
// development and tests only — production supplies a KMS/HSM-backed KeyProvider.
// Never hardcode a KEK in production (CLAUDE.md §7 guardrail 6).
type StaticKeyProvider struct {
	provider Provider
	keyID    string
	kek      []byte
}

// NewStaticKeyProvider returns a StaticKeyProvider for a 32-byte KEK.
func NewStaticKeyProvider(keyID string, kek []byte) (*StaticKeyProvider, error) {
	if len(kek) != KeySize {
		return nil, fmt.Errorf("crypto: KEK must be %d bytes, got %d", KeySize, len(kek))
	}
	if keyID == "" {
		return nil, errors.New("crypto: KEK key id must not be empty")
	}
	return &StaticKeyProvider{provider: Default, keyID: keyID, kek: kek}, nil
}

// NewStaticKeyProviderFromBase64 decodes a base64 (std encoding) 32-byte KEK.
func NewStaticKeyProviderFromBase64(keyID, b64 string) (*StaticKeyProvider, error) {
	kek, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return nil, fmt.Errorf("crypto: decode KEK: %w", err)
	}
	return NewStaticKeyProvider(keyID, kek)
}

// KeyID returns the KEK identifier.
func (p *StaticKeyProvider) KeyID() string { return p.keyID }

// WrapKey wraps a data key under the static KEK.
func (p *StaticKeyProvider) WrapKey(_ context.Context, dek []byte) ([]byte, error) {
	return p.provider.Encrypt(p.kek, dek, []byte(p.keyID))
}

// UnwrapKey unwraps a data key wrapped by WrapKey.
func (p *StaticKeyProvider) UnwrapKey(_ context.Context, wrapped []byte) ([]byte, error) {
	return p.provider.Decrypt(p.kek, wrapped, []byte(p.keyID))
}

// Envelope performs envelope encryption: each value gets a fresh data key (DEK)
// that encrypts the value and is itself wrapped by the KeyProvider's KEK.
type Envelope struct {
	provider Provider
	keys     KeyProvider
}

// NewEnvelope returns an Envelope using the given KeyProvider.
func NewEnvelope(keys KeyProvider) *Envelope {
	return &Envelope{provider: Default, keys: keys}
}

// Sealed is the at-rest representation of an envelope-encrypted value.
type Sealed struct {
	KeyID      string
	WrappedDEK []byte
	Ciphertext []byte // nonce-prefixed AES-256-GCM
}

// Seal encrypts plaintext, binding aad (for example a column or row identifier)
// into the value's AEAD so a ciphertext cannot be relocated to another row.
func (e *Envelope) Seal(ctx context.Context, plaintext, aad []byte) (Sealed, error) {
	dek, err := e.provider.Random(KeySize)
	if err != nil {
		return Sealed{}, err
	}
	ct, err := e.provider.Encrypt(dek, plaintext, aad)
	if err != nil {
		return Sealed{}, err
	}
	wrapped, err := e.keys.WrapKey(ctx, dek)
	if err != nil {
		return Sealed{}, fmt.Errorf("crypto: wrap dek: %w", err)
	}
	return Sealed{KeyID: e.keys.KeyID(), WrappedDEK: wrapped, Ciphertext: ct}, nil
}

// Open decrypts a Sealed value.
func (e *Envelope) Open(ctx context.Context, s Sealed, aad []byte) ([]byte, error) {
	dek, err := e.keys.UnwrapKey(ctx, s.WrappedDEK)
	if err != nil {
		return nil, fmt.Errorf("crypto: unwrap dek: %w", err)
	}
	return e.provider.Decrypt(dek, s.Ciphertext, aad)
}

// envelopeFormatV1 is the version byte of the on-disk Sealed encoding.
const envelopeFormatV1 byte = 1

// Encode serializes a Sealed value into a self-describing, versioned byte slice
// suitable for a bytea column:
//
//	v1 || uint16(len keyID) || keyID || uint32(len wrappedDEK) || wrappedDEK || ciphertext
func (s Sealed) Encode() ([]byte, error) {
	if len(s.KeyID) > 0xffff {
		return nil, errors.New("crypto: key id too long")
	}
	out := make([]byte, 0, 1+2+len(s.KeyID)+4+len(s.WrappedDEK)+len(s.Ciphertext))
	out = append(out, envelopeFormatV1)
	out = binary.BigEndian.AppendUint16(out, uint16(len(s.KeyID)))
	out = append(out, s.KeyID...)
	out = binary.BigEndian.AppendUint32(out, uint32(len(s.WrappedDEK)))
	out = append(out, s.WrappedDEK...)
	out = append(out, s.Ciphertext...)
	return out, nil
}

// DecodeSealed parses bytes produced by Sealed.Encode.
func DecodeSealed(b []byte) (Sealed, error) {
	if len(b) < 1 || b[0] != envelopeFormatV1 {
		return Sealed{}, errors.New("crypto: unknown envelope format")
	}
	b = b[1:]
	if len(b) < 2 {
		return Sealed{}, errors.New("crypto: truncated envelope (keyID length)")
	}
	keyLen := int(binary.BigEndian.Uint16(b))
	b = b[2:]
	if len(b) < keyLen+4 {
		return Sealed{}, errors.New("crypto: truncated envelope (keyID)")
	}
	keyID := string(b[:keyLen])
	b = b[keyLen:]
	wrapLen := int(binary.BigEndian.Uint32(b))
	b = b[4:]
	if len(b) < wrapLen {
		return Sealed{}, errors.New("crypto: truncated envelope (wrapped dek)")
	}
	return Sealed{
		KeyID:      keyID,
		WrappedDEK: append([]byte(nil), b[:wrapLen]...),
		Ciphertext: append([]byte(nil), b[wrapLen:]...),
	}, nil
}
