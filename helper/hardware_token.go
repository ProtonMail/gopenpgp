package helper

import (
	"bytes"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/ecdh"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/constants"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/pkg/errors"
)

// GetEncryptedKeyFieldsFromMessage parses a PGP message and returns the
// encrypted key material from the first PKESK (Public-Key Encrypted Session
// Key) packet. This is needed for hardware token integrations where the
// encrypted material must be sent to an external device for decryption.
//
// Returns:
//   - keyID: the ID of the key the message is encrypted to
//   - algo: the public key algorithm (e.g., ECDH, RSA)
//   - mpi1: the first encrypted MPI field (ephemeral point for ECDH,
//     encrypted session key for RSA)
//   - mpi2: the second encrypted MPI field (wrapped session key for ECDH,
//     nil for RSA)
func GetEncryptedKeyFieldsFromMessage(pgpMessage *crypto.PGPMessage) (keyID uint64, algo int, mpi1, mpi2 []byte, err error) {
	packets := packet.NewReader(bytes.NewReader(pgpMessage.GetBinary()))

	for {
		var p packet.Packet
		if p, err = packets.Next(); err == io.EOF {
			err = errors.New("gopenpgp: no encrypted key packet found in message")
			return
		}
		if err != nil {
			err = errors.Wrap(err, "gopenpgp: unable to parse packet")
			return
		}

		if ek, ok := p.(*packet.EncryptedKey); ok {
			keyID = ek.KeyId
			algo = int(ek.Algo)
			mpi1 = ek.GetEncryptedMPI1()
			mpi2 = ek.GetEncryptedMPI2()
			err = nil
			return
		}
	}
}

// GetEncryptedMPI1FromMessage extracts the first encrypted MPI field from
// the first PKESK packet in a PGP message. For ECDH, this is the ephemeral
// public key point needed by a hardware token to compute the shared secret.
// For RSA, this is the encrypted session key.
//
// This is a gomobile-compatible wrapper around GetEncryptedKeyFieldsFromMessage.
func GetEncryptedMPI1FromMessage(pgpMessage *crypto.PGPMessage) ([]byte, error) {
	_, _, mpi1, _, err := GetEncryptedKeyFieldsFromMessage(pgpMessage)
	return mpi1, err
}

// DecryptMessageWithECDHSharedSecret decrypts a PGP message encrypted to an
// ECDH key, given the raw shared secret from an external Decaps operation
// (e.g., a YubiKey PSO:DECIPHER command).
//
// This function completes the ECDH key agreement by performing the KDF
// (RFC 6637 §8) and AES key unwrap (RFC 3394), then decrypts the message
// with the recovered session key. The private key is never needed.
//
// Parameters:
//   - pgpMessage: the full encrypted PGP message
//   - publicKey: the recipient's armored public key (provides ECDH parameters
//     for the KDF: curve OID, KDF hash, KEK algorithm, and fingerprint)
//   - sharedSecret: the raw ECDH shared secret (zb) returned by the hardware
//     token's Decaps operation
func DecryptMessageWithECDHSharedSecret(
	pgpMessage *crypto.PGPMessage,
	publicKey string,
	sharedSecret []byte,
) (plaintext []byte, err error) {
	// Parse the public key to find the ECDH subkey.
	publicKeyObj, err := crypto.NewKeyFromArmored(publicKey)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to parse public key")
	}

	entity := publicKeyObj.GetEntity()
	ecdhPub, oid, fingerprint, err := findECDHKey(entity)
	if err != nil {
		return nil, err
	}

	// Extract the wrapped session key (MPI2) from the message.
	_, _, _, wrappedKey, err := GetEncryptedKeyFieldsFromMessage(pgpMessage)
	if err != nil {
		return nil, err
	}
	if wrappedKey == nil {
		return nil, errors.New("gopenpgp: no wrapped key (MPI2) found in ECDH encrypted message")
	}

	// Complete ECDH: KDF + AES key unwrap using the shared secret.
	unwrapped, err := ecdh.DecryptWithSharedSecret(ecdhPub, sharedSecret, wrappedKey, oid, fingerprint)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to unwrap session key with shared secret")
	}

	// Parse the unwrapped key material:
	// m = symm_alg_ID || session key || checksum
	if len(unwrapped) < 3 {
		return nil, errors.New("gopenpgp: unwrapped key material too short")
	}

	cipherFunc := packet.CipherFunction(unwrapped[0])
	if !cipherFunc.IsSupported() {
		return nil, errors.New("gopenpgp: unsupported cipher in unwrapped session key")
	}

	// Strip algorithm ID byte and 2-byte checksum to get the raw session key.
	sessionKeyBytes := unwrapped[1 : len(unwrapped)-2]
	algoName, err := cipherFuncToName(cipherFunc)
	if err != nil {
		return nil, err
	}

	sessionKey := crypto.NewSessionKeyFromToken(sessionKeyBytes, algoName)

	// Split the message and decrypt the data packet with the session key.
	splitMsg, err := pgpMessage.SplitMessage()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to split message")
	}

	message, err := sessionKey.Decrypt(splitMsg.GetBinaryDataPacket())
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: unable to decrypt message with session key")
	}

	return message.GetBinary(), nil
}

// findECDHKey searches an OpenPGP entity for the first ECDH encryption subkey.
// Falls back to the primary key if it is an ECDH key. Returns the ECDH public
// key, encoded curve OID, and key fingerprint needed for the KDF.
func findECDHKey(entity *openpgp.Entity) (ecdhPub *ecdh.PublicKey, oid, fingerprint []byte, err error) {
	// Check subkeys first (preferred for encryption).
	for _, sub := range entity.Subkeys {
		if sub.PublicKey.PubKeyAlgo == packet.PubKeyAlgoECDH {
			pub, ok := sub.PublicKey.PublicKey.(*ecdh.PublicKey)
			if !ok {
				continue
			}
			return pub, sub.PublicKey.GetECDHOid(), sub.PublicKey.Fingerprint, nil
		}
	}

	// Fall back to primary key.
	if entity.PrimaryKey.PubKeyAlgo == packet.PubKeyAlgoECDH {
		pub, ok := entity.PrimaryKey.PublicKey.(*ecdh.PublicKey)
		if !ok {
			return nil, nil, nil, errors.New("gopenpgp: primary key is ECDH but has unexpected type")
		}
		return pub, entity.PrimaryKey.GetECDHOid(), entity.PrimaryKey.Fingerprint, nil
	}

	return nil, nil, nil, errors.New("gopenpgp: no ECDH key found in the provided public key")
}

// cipherFuncToName maps a packet.CipherFunction to the string name used by
// crypto.NewSessionKeyFromToken.
func cipherFuncToName(cf packet.CipherFunction) (string, error) {
	switch cf {
	case packet.Cipher3DES:
		return constants.ThreeDES, nil
	case packet.CipherCAST5:
		return constants.CAST5, nil
	case packet.CipherAES128:
		return constants.AES128, nil
	case packet.CipherAES192:
		return constants.AES192, nil
	case packet.CipherAES256:
		return constants.AES256, nil
	default:
		return "", errors.New("gopenpgp: unsupported cipher function")
	}
}
