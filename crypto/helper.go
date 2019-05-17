package crypto

import (
	"errors"
)

func (pgp *GopenPGP) EncryptMessageArmoredHelper(publicKey, plaintext string) (ciphertext string, err error){
	var publicKeyRing *KeyRing
	var pgpMessage *PGPMessage

	var cleartextMessage = NewCleartextMessage(plaintext)

	if publicKeyRing, err = pgp.BuildKeyRingArmored(publicKey); err != nil {
		return "", err
	}

	if pgpMessage, err = publicKeyRing.EncryptMessage(cleartextMessage, nil, false); err != nil {
		return "", err
	}

	if ciphertext, err = pgpMessage.GetArmored(); err != nil {
		return "", err
	}

	return ciphertext, nil
}

func (pgp *GopenPGP) EncryptSignMessageArmoredHelper(
	publicKey, privateKey, passphrase, plaintext string,
) (ciphertext string, err error){
	var publicKeyRing, privateKeyRing *KeyRing
	var pgpMessage *PGPMessage

	var cleartextMessage = NewCleartextMessage(plaintext)

	if publicKeyRing, err = pgp.BuildKeyRingArmored(publicKey); err != nil {
		return "", err
	}

	if privateKeyRing, err = pgp.BuildKeyRingArmored(privateKey); err != nil {
		return "", err
	}

	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
		return "", err
	}

	if pgpMessage, err = publicKeyRing.EncryptMessage(cleartextMessage, privateKeyRing, false); err != nil {
		return "", err
	}

	if ciphertext, err = pgpMessage.GetArmored(); err != nil {
		return "", err
	}

	return ciphertext, nil
}

func (pgp *GopenPGP) DecryptMessageArmoredHelper(
	privateKey, passphrase, ciphertext string,
) (plaintext string, err error){
	var privateKeyRing *KeyRing
	var pgpMessage *PGPMessage
	var cleartextMessage *CleartextMessage

	if privateKeyRing, err = pgp.BuildKeyRingArmored(privateKey); err != nil {
		return "", err
	}

	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
		return "", err
	}

	if pgpMessage, err = NewPGPMessageFromArmored(ciphertext); err != nil {
		return "", err
	}

	if cleartextMessage, err = privateKeyRing.DecryptMessage(pgpMessage, nil, 0); err != nil {
		return "", err
	}

	return cleartextMessage.GetString(), nil
}

func (pgp *GopenPGP) DecryptVerifyMessageArmoredHelper(
	publicKey, privateKey, passphrase, ciphertext string,
) (plaintext string, err error){
	var publicKeyRing, privateKeyRing *KeyRing
	var pgpMessage *PGPMessage
	var cleartextMessage *CleartextMessage

	if publicKeyRing, err = pgp.BuildKeyRingArmored(publicKey); err != nil {
		return "", err
	}

	if privateKeyRing, err = pgp.BuildKeyRingArmored(privateKey); err != nil {
		return "", err
	}

	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
		return "", err
	}

	if pgpMessage, err = NewPGPMessageFromArmored(ciphertext); err != nil {
		return "", err
	}

	if cleartextMessage, err = privateKeyRing.DecryptMessage(pgpMessage, publicKeyRing, pgp.GetUnixTime()); err != nil {
		return "", err
	}

	if !cleartextMessage.IsVerified() {
		return "", errors.New("gopenpgp: unable to verify message")
	}

	return cleartextMessage.GetString(), nil
}
