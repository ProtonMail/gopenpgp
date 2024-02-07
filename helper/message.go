package helper

import "github.com/ProtonMail/gopenpgp/v2/crypto"

// EncryptPGPMessageToAdditionalKey decrypts the session key of the input PGPSplitMessage with a private key in keyRing
// and encrypts it towards the additionalKeys by adding the additional key packets to the input PGPSplitMessage.
// If successful, new key packets are added to message.
// * messageToModify : The encrypted pgp message that should be modified
// * keyRing         : The private keys to decrypt the session key in the messageToModify.
// * additionalKey   : The public keys the message should be additionally encrypted to.
func EncryptPGPMessageToAdditionalKey(messageToModify *crypto.PGPSplitMessage, keyRing *crypto.KeyRing, additionalKey *crypto.KeyRing) error {
	sessionKey, err := keyRing.DecryptSessionKey(messageToModify.KeyPacket)
	if err != nil {
		return err
	}
	additionalKeyPacket, err := additionalKey.EncryptSessionKey(sessionKey)
	if err != nil {
		return err
	}
	messageToModify.KeyPacket = append(messageToModify.KeyPacket, additionalKeyPacket...)
	return nil
}
