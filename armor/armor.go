package armor

import (
	"bytes"
	"errors"
	"github.com/ProtonMail/go-pm-crypto/internal"
	"github.com/ProtonMail/go-pm-crypto/models"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/clearsign"
	"golang.org/x/crypto/openpgp/packet"
	"io"
	"io/ioutil"
)

// ArmorKey make bytes input key to armor format
func ArmorKey(input []byte) (string, error) {
	return ArmorWithType(input, PUBLIC_KEY_HEADER)
}

// ArmorWithType make bytes input to armor format
func ArmorWithType(input []byte, armorType string) (string, error) {
	var b bytes.Buffer
	w, err := armor.Encode(&b, armorType, internal.ArmorHeaders)
	if err != nil {
		return "", err
	}
	_, err = w.Write(input)
	if err != nil {
		return "", err
	}
	w.Close()
	return b.String(), nil
}

// Unarmor an armored key to bytes key
func Unarmor(input string) ([]byte, error) {
	b, err := internal.Unarmor(input)
	if err != nil {
		return nil, err
	}
	return ioutil.ReadAll(b.Body)
}

//ReadClearSignedMessage read clear message from a clearsign package
func ReadClearSignedMessage(signedMessage string) (string, error) {
	modulusBlock, rest := clearsign.Decode([]byte(signedMessage))
	if len(rest) != 0 {
		return "", errors.New("pmapi: extra data after modulus")
	}
	return string(modulusBlock.Bytes), nil
}

//SeparateKeyAndData ...
func SplitArmor(encrypted string) (*models.EncryptedSplit, error) {

	var err error

	encryptedRaw, err := Unarmor(encrypted)
	if err != nil {
		return nil, err
	}

	encryptedReader := bytes.NewReader(encryptedRaw)

	//kr *KeyRing, r io.Reader) (key *SymmetricKey, symEncryptedData []byte,
	packets := packet.NewReader(encryptedReader)

	outSplit := &models.EncryptedSplit{}

	// Save encrypted key and signature apart
	var ek *packet.EncryptedKey
	// var decryptErr error
	for {
		var p packet.Packet
		if p, err = packets.Next(); err == io.EOF {
			err = nil
			break
		}
		switch p := p.(type) {
		case *packet.EncryptedKey:
			// We got an encrypted key. Try to decrypt it with each available key
			if ek != nil && ek.Key != nil {
				break
			}
			ek = p
			break
		case *packet.SymmetricallyEncrypted:
			var packetContents []byte
			if packetContents, err = ioutil.ReadAll(p.Contents); err != nil {
				return nil, err
			}

			encodedLength := encodedLength(len(packetContents) + 1)
			var symEncryptedData []byte
			symEncryptedData = append(symEncryptedData, byte(210))
			symEncryptedData = append(symEncryptedData, encodedLength...)
			symEncryptedData = append(symEncryptedData, byte(1))
			symEncryptedData = append(symEncryptedData, packetContents...)

			outSplit.DataPacket = symEncryptedData
			break

		}
	}

	var buf bytes.Buffer
	ek.Serialize(&buf)
	outSplit.KeyPacket = buf.Bytes()

	return outSplit, err
}

//encode length based on 4.2.2. in the RFC
func encodedLength(length int) (b []byte) {
	if length < 192 {
		b = append(b, byte(length))
	} else if length < 8384 {
		length = length - 192
		b = append(b, 192+byte(length>>8))
		b = append(b, byte(length))
	} else {
		b = append(b, byte(255))
		b = append(b, byte(length>>24))
		b = append(b, byte(length>>16))
		b = append(b, byte(length>>8))
		b = append(b, byte(length))
	}
	return
}
