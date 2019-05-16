package crypto

import (
	"encoding/base64"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"regexp"
	"runtime"

	"github.com/ProtonMail/gopenpgp/armor"
	"github.com/ProtonMail/gopenpgp/constants"
	"github.com/ProtonMail/gopenpgp/internal"

	"golang.org/x/crypto/openpgp/packet"
)

// ---- MODELS -----

// PlainTextMessage stores an unencrypted text message.
type CleartextMessage struct {
	// The content of the message
	Text string
	// If the decoded message was correctly signed. See constants.SIGNATURE* for all values
 	Verified int
}

// BinaryMessage stores an unencrypted binary message.
type BinaryMessage struct {
	// The content of the message
	Data []byte
	// If the decoded message was correctly signed. See constants.SIGNATURE* for all values
 	Verified int
}

// PGPMessage stores a PGP-encrypted message.
type PGPMessage struct {
	// The content of the message
	Data []byte
}

// PGPMessage stores a PGP-encoded detached signature.
type PGPSignature struct {
	// The content of the message
	Data []byte
}

// PGPSplitMessage contains a separate session key packet and symmetrically
// encrypted data packet.
type PGPSplitMessage struct {
	DataPacket []byte
	KeyPacket  []byte
	Algo       string
}

// ---- GENERATORS -----
func NewCleartextMessage(text string) (*CleartextMessage) {
	return &CleartextMessage {
		Text: text,
		Verified: constants.SIGNATURE_NOT_SIGNED,
	}
}

func NewBinaryMessage(data []byte) (*BinaryMessage) {
	return &BinaryMessage {
		Data: data,
		Verified: constants.SIGNATURE_NOT_SIGNED,
	}
}

func NewPGPMessageFromArmored(armored string) (*PGPMessage, error) {
	encryptedIO, err := internal.Unarmor(armored)
	if err != nil {
		return nil, err
	}

	message, err := ioutil.ReadAll(encryptedIO.Body)
	if err != nil {
		return nil, err
	}

	return &PGPMessage {
		Data: message,
	}, nil
}

func NewPGPMessage(data []byte) (*PGPMessage) {
	return &PGPMessage {
		Data: data,
	}
}

func NewPGPSignatureFromArmored(armored string) (*PGPSignature, error) {
	encryptedIO, err := internal.Unarmor(armored)
	if err != nil {
		return nil, err
	}

	signature, err := ioutil.ReadAll(encryptedIO.Body)
	if err != nil {
		return nil, err
	}

	return &PGPSignature {
		Data: signature,
	}, nil
}

func NewPGPSignature(data []byte) (*PGPSignature) {
	return &PGPSignature {
		Data: data,
	}
}

// ---- MODEL METHODS -----
func (msg *CleartextMessage) GetVerification() int {
	return msg.Verified
}

func (msg *CleartextMessage) IsVerified() bool {
	return msg.Verified == constants.SIGNATURE_OK
}

func (msg *CleartextMessage) GetString() string {
	return msg.Text
}

func (msg *CleartextMessage) NewReader() io.Reader {
	return bytes.NewReader(bytes.NewBufferString(msg.GetString()).Bytes())
}

func (msg *BinaryMessage) GetVerification() int {
	return msg.Verified
}

func (msg *BinaryMessage) IsVerified() bool {
	return msg.Verified == constants.SIGNATURE_OK
}


func (msg *BinaryMessage) GetBinary() []byte {
	return msg.Data
}

func (msg *BinaryMessage) NewReader() io.Reader {
	return bytes.NewReader(msg.GetBinary())
}


func (msg *BinaryMessage) GetBase64() string {
	return base64.StdEncoding.EncodeToString(msg.Data)
}

func (msg *PGPMessage) GetBinary() []byte {
	return msg.Data
}

func (msg *PGPMessage) NewReader() io.Reader {
	return bytes.NewReader(msg.GetBinary())
}

func (msg *PGPMessage) GetArmored() (string, error) {
	return armor.ArmorWithType(msg.Data, constants.PGPMessageHeader)
}

// SeparateKeyAndData returns the first keypacket and the (hopefully unique) dataPacket (not verified)
// FIXME: add support for multiple keypackets
func (msg *PGPMessage) SeparateKeyAndData(estimatedLength, garbageCollector int)(outSplit *PGPSplitMessage, err error) {
	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	packets := packet.NewReader(bytes.NewReader(msg.Data))
	outSplit = &PGPSplitMessage{}
	gcCounter := 0

	// Store encrypted key and symmetrically encrypted packet separately
	var encryptedKey *packet.EncryptedKey
	var decryptErr error
	for {
		var p packet.Packet
		if p, err = packets.Next(); err == io.EOF {
			err = nil
			break
		}
		switch p := p.(type) {
		case *packet.EncryptedKey:
			if encryptedKey != nil && encryptedKey.Key != nil {
				break
			}
			encryptedKey = p

		case *packet.SymmetricallyEncrypted:
			// FIXME
			// The code below is optimized to not
			var b bytes.Buffer
			// 2^16 is an estimation of the size difference between input and output, the size difference is most probably
			// 16 bytes at a maximum though.
			// We need to avoid triggering a grow from the system as this will allocate too much memory causing problems
			// in low-memory environments
			b.Grow(1<<16 + estimatedLength)
			// empty encoded length + start byte
			b.Write(make([]byte, 6))
			b.WriteByte(byte(1))
			actualLength := 1
			block := make([]byte, 128)
			for {
				n, err := p.Contents.Read(block)
				if err == io.EOF {
					break
				}
				b.Write(block[:n])
				actualLength += n
				gcCounter += n
				if gcCounter > garbageCollector && garbageCollector > 0 {
					runtime.GC()
					gcCounter = 0
				}
			}

			// quick encoding
			symEncryptedData := b.Bytes()
			if actualLength < 192 {
				symEncryptedData[4] = byte(210)
				symEncryptedData[5] = byte(actualLength)
				symEncryptedData = symEncryptedData[4:]
			} else if actualLength < 8384 {
				actualLength = actualLength - 192
				symEncryptedData[3] = byte(210)
				symEncryptedData[4] = 192 + byte(actualLength>>8)
				symEncryptedData[5] = byte(actualLength)
				symEncryptedData = symEncryptedData[3:]
			} else {
				symEncryptedData[0] = byte(210)
				symEncryptedData[1] = byte(255)
				symEncryptedData[2] = byte(actualLength >> 24)
				symEncryptedData[3] = byte(actualLength >> 16)
				symEncryptedData[4] = byte(actualLength >> 8)
				symEncryptedData[5] = byte(actualLength)
			}

			outSplit.DataPacket = symEncryptedData
		}
	}
	if decryptErr != nil {
		return nil, fmt.Errorf("gopenpgp: cannot decrypt encrypted key packet: %v", decryptErr)
	}
	if encryptedKey == nil {
		return nil, errors.New("gopenpgp: packets don't include an encrypted key packet")
	}


	var buf bytes.Buffer
	if err := encryptedKey.Serialize(&buf); err != nil {
		return nil, fmt.Errorf("gopenpgp: cannot serialize encrypted key: %v", err)
	}
	outSplit.KeyPacket = buf.Bytes()

	return outSplit, nil
}


func (msg *PGPSignature) GetBinary() []byte {
	return msg.Data
}

func (msg *PGPSignature) GetArmored() (string, error) {
	return armor.ArmorWithType(msg.Data, constants.PGPSignatureHeader)
}

// ---- UTILS -----

// IsPGPMessage check if data if has armored PGP message format.
func (pgp *GopenPGP) IsPGPMessage(data string) bool {
	re := regexp.MustCompile("^-----BEGIN " + constants.PGPMessageHeader + "-----(?s:.+)-----END " +
		constants.PGPMessageHeader + "-----");
	return re.MatchString(data);
}
