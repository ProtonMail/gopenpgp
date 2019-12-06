package crypto

import (
	"bytes"
	"errors"
	"io"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// Encrypt encrypts a PlainMessage to PGPMessage with a SymmetricKey
// * message : The plain data as a PlainMessage
// * password: A password that will be derived into an encryption key
// * output  : The encrypted data as PGPMessage
func EncryptMessageWithPassword(message *PlainMessage, password []byte) (*PGPMessage, error) {
	encrypted, err := passwordEncrypt(message.GetBinary(), password)
	if err != nil {
		return nil, err
	}

	return NewPGPMessage(encrypted), nil
}

// Decrypt decrypts password protected pgp binary messages
// * encrypted: The encrypted data as PGPMessage
// * password: A password that will be derived into an encryption key
// * output: The decrypted data as PlainMessage
func DecryptMessageWithPassword(message *PGPMessage, password []byte) (*PlainMessage, error) {
	decrypted, err := passwordDecrypt(message.NewReader(), password)
	if err != nil {
		return nil, err
	}

	binMessage := NewPlainMessage(decrypted)
	return binMessage, nil
}


// DecryptSessionKeyWithPassword decrypts the binary symmetrically encrypted
// session key packet and returns the session key.
func DecryptSessionKeyWithPassword(keyPacket, password []byte) (*SessionKey, error) {
	keyReader := bytes.NewReader(keyPacket)
	packets := packet.NewReader(keyReader)

	var symKeys []*packet.SymmetricKeyEncrypted
	for {

		var p packet.Packet
		var err error
		if p, err = packets.Next(); err != nil {
			break
		}

		switch p := p.(type) {
		case *packet.SymmetricKeyEncrypted:
			symKeys = append(symKeys, p)
		}
	}

	pwdRaw := []byte(password)
	// Try the symmetric passphrase first
	if len(symKeys) != 0 && pwdRaw != nil {
		for _, s := range symKeys {
			key, cipherFunc, err := s.Decrypt(pwdRaw)
			if err == nil {
				return &SessionKey{
					Key:  key,
					Algo: getAlgo(cipherFunc),
				}, nil
			}

		}
	}

	return nil, errors.New("gopenpgp: password incorrect")
}

// EncryptSessionKeyWithPassword encrypts the session key with the password and
// returns a binary symmetrically encrypted session key packet.
func EncryptSessionKeyWithPassword(sk *SessionKey, password []byte) ([]byte, error) {
	outbuf := &bytes.Buffer{}

	cf := sk.GetCipherFunc()

	if len(password) <= 0 {
		return nil, errors.New("gopenpgp: password can't be empty")
	}

	pwdRaw := []byte(password)

	config := &packet.Config{
		DefaultCipher: cf,
	}

	err := packet.SerializeSymmetricKeyEncryptedReuseKey(outbuf, sk.Key, pwdRaw, config)
	if err != nil {
		return nil, err
	}
	return outbuf.Bytes(), nil
}

// ----- INTERNAL FUNCTIONS ------

func passwordEncrypt(message []byte, password []byte) ([]byte, error) {
	var outBuf bytes.Buffer

	config := &packet.Config{
		Time:          getTimeGenerator(),
	}

	encryptWriter, err := openpgp.SymmetricallyEncrypt(&outBuf, password, nil, config)
	if err != nil {
		return nil, err
	}
	_, err = encryptWriter.Write(message)
	if err != nil {
		return nil, err
	}

	err = encryptWriter.Close()
	if err != nil {
		return nil, err
	}

	return outBuf.Bytes(), nil
}

func passwordDecrypt(encryptedIO io.Reader, password []byte) ([]byte, error) {
	firstTimeCalled := true
	var prompt = func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if firstTimeCalled {
			firstTimeCalled = false
			return password, nil
		}
		return nil, errors.New("gopenpgp: wrong password in symmetric decryption")
	}

	config := &packet.Config{
		Time: getTimeGenerator(),
	}
	md, err := openpgp.ReadMessage(encryptedIO, nil, prompt, config)
	if err != nil {
		return nil, err
	}

	messageBuf := bytes.NewBuffer(nil)
	_, err = io.Copy(messageBuf, md.UnverifiedBody)
	if err != nil {
		return nil, err
	}

	return messageBuf.Bytes(), nil
}

