// server/platform/tokenutils/tokens.go
package tokenutils

import (
	"crypto/rand"
	"crypto/subtle" // For constant-time comparison
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	DefaultPublicIDPrefix = "kxt" // Example: Knoxville Token
	PublicIDRandomLength  = 12    // Number of random bytes for the ID suffix -> ~16 chars
	SecretDefaultLength   = 32    // Number of random bytes for secret -> ~43 chars
)

// Argon2id parameters - make these constants or configurable
const (
	argon2Memory      uint32 = 64 * 1024 // 64 MiB
	argon2Iterations  uint32 = 3
	argon2Parallelism uint8  = 2 // Number of threads
	argon2SaltLength  uint32 = 16
	argon2KeyLength   uint32 = 32 // Length of the derived key (hash)
)

var (
	ErrInvalidHashFormat   = errors.New("invalid encoded hash format")
	ErrIncompatibleVersion = errors.New("incompatible argon2 version")
	ErrVerificationFailed  = errors.New("secret verification failed") // Generic verification failure
)

// --- Generation Functions ---

// generateRandomBytes generates n cryptographically secure random bytes.
func generateRandomBytes(n uint32) ([]byte, error) {
	if n == 0 {
		return nil, errors.New("number of bytes must be positive")
	}
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return nil, fmt.Errorf("failed to read crypto/rand: %w", err)
	}
	return b, nil
}

// GenerateTokenSecret creates a secure random string suitable for the secret part of a token.
func GenerateTokenSecret(length uint32) (string, error) {
	if length == 0 {
		length = SecretDefaultLength
	}
	randomBytes, err := generateRandomBytes(length)
	if err != nil {
		return "", err
	}
	// Use RawURLEncoding for a URL-safe string without padding '=' characters.
	secret := base64.RawURLEncoding.EncodeToString(randomBytes)
	return secret, nil
}

// GeneratePublicID creates a unique public identifier for a token.
func GeneratePublicID(prefix string) (string, error) {
	if prefix == "" {
		prefix = DefaultPublicIDPrefix
	}
	prefix = strings.ToLower(strings.TrimSuffix(prefix, "_")) // Ensure lowercase and no trailing underscore

	randomBytes, err := generateRandomBytes(PublicIDRandomLength)
	if err != nil {
		return "", fmt.Errorf("failed generating random part for public ID: %w", err)
	}
	randomPart := base64.RawURLEncoding.EncodeToString(randomBytes)

	publicID := fmt.Sprintf("%s_%s", prefix, randomPart)
	return publicID, nil
}

// --- Hashing Function ---

// hashSecret hashes the provided secret using Argon2id and returns the standard encoded hash format.
func HashSecret(secret string) (string, error) {
	if secret == "" {
		return "", errors.New("secret cannot be empty")
	}

	// 1. Generate a unique random salt *for each hash*
	salt, err := generateRandomBytes(argon2SaltLength)
	if err != nil {
		return "", fmt.Errorf("failed generating salt: %w", err)
	}

	// 2. Hash the secret using argon2.IDKey
	hash := argon2.IDKey([]byte(secret), salt, argon2Iterations, argon2Memory, argon2Parallelism, argon2KeyLength)

	// 3. Encode parameters, salt, and hash into a single string for storage
	b64Salt := base64.RawStdEncoding.EncodeToString(salt) // Use RawStdEncoding matching Argon2 spec examples
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)

	// Standard Argon2 encoded format string: $argon2id$v=19$m=<mem>,t=<iter>,p=<para>$<salt>$<hash>
	encodedHash := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Iterations, argon2Parallelism, b64Salt, b64Hash)

	return encodedHash, nil
}

// --- Verification Function ---

// VerifySecret compares a plain text secret against a standard Argon2id encoded hash string.
func VerifySecret(secret, encodedHash string) (verified bool, err error) {
	if secret == "" || encodedHash == "" {
		return false, errors.New("secret and encoded hash must not be empty")
	}

	// 1. Parse the encoded hash string
	params, salt, hashDigest, err := decodeHash(encodedHash)
	if err != nil {
		return false, fmt.Errorf("failed to decode hash: %w", err)
	}

	// 2. Re-compute the hash of the provided secret using the *extracted* salt and params
	comparisonHash := argon2.IDKey([]byte(secret), salt, params.iterations, params.memory, params.parallelism, params.keyLength)

	// 3. Compare the computed hash with the extracted hash *in constant time*
	if subtle.ConstantTimeCompare(hashDigest, comparisonHash) == 1 {
		return true, nil // Match!
	}

	// No match, return specific (but generic) error or just false
	return false, nil // Return false for no match, nil error
	// return false, ErrVerificationFailed // Alternative: return specific error
}

// argon2Params holds the parameters extracted from the encoded hash string.
type argon2Params struct {
	memory      uint32
	iterations  uint32
	parallelism uint8
	keyLength   uint32 // Though keyLength is not encoded, we know it from constants
}

// decodeHash parses the standard Argon2 encoded hash string format.
// Format: $argon2id$v=19$m=<mem>,t=<iter>,p=<para>$<salt>$<hash>
func decodeHash(encodedHash string) (params *argon2Params, salt, hash []byte, err error) {
	vals := strings.Split(encodedHash, "$")
	// Expecting 6 parts: "" "argon2id" "v=19" "m=...,t=...,p=..." "salt" "hash"
	if len(vals) != 6 {
		return nil, nil, nil, ErrInvalidHashFormat
	}

	// Check algorithm type
	if vals[1] != "argon2id" {
		return nil, nil, nil, fmt.Errorf("%w: unsupported algorithm %s", ErrInvalidHashFormat, vals[1])
	}

	// Check version
	var version int
	_, err = fmt.Sscanf(vals[2], "v=%d", &version)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: failed parsing version: %v", ErrInvalidHashFormat, err)
	}
	if version != argon2.Version {
		return nil, nil, nil, fmt.Errorf("%w: expected version %d, got %d", ErrIncompatibleVersion, argon2.Version, version)
	}

	// Parse parameters
	params = &argon2Params{keyLength: argon2KeyLength} // Initialize with known keyLength
	_, err = fmt.Sscanf(vals[3], "m=%d,t=%d,p=%d", &params.memory, &params.iterations, &params.parallelism)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: failed parsing parameters: %v", ErrInvalidHashFormat, err)
	}

	// Decode salt
	salt, err = base64.RawStdEncoding.DecodeString(vals[4])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: failed decoding salt: %v", ErrInvalidHashFormat, err)
	}

	// Decode hash digest
	hash, err = base64.RawStdEncoding.DecodeString(vals[5])
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: failed decoding hash: %v", ErrInvalidHashFormat, err)
	}

	// Basic validation on decoded lengths (optional but good practice)
	if uint32(len(salt)) != argon2SaltLength {
		// Log inconsistency? Parameters might differ from constants used during hashing.
		// The verification function *uses* the parameters from the hash string itself,
		// so this might not be a fatal error, but could indicate mixed settings over time.
		// For now, just ensure salt is not empty.
		if len(salt) == 0 {
			return nil, nil, nil, fmt.Errorf("%w: decoded salt is empty", ErrInvalidHashFormat)
		}
	}
	if uint32(len(hash)) != params.keyLength {
		return nil, nil, nil, fmt.Errorf("%w: decoded hash length (%d) does not match expected key length (%d)", ErrInvalidHashFormat, len(hash), params.keyLength)
	}

	return params, salt, hash, nil
}
