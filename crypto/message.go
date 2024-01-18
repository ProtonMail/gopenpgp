package crypto

import (
	"bytes"
	"encoding/json"
	goerrors "errors"
	"io"
	"regexp"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v3/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/internal"
	"github.com/pkg/errors"
)

// ---- MODELS -----

type LiteralMetadata struct {
	// If the content is text or binary
	isUTF8 bool
	// The encrypted message's filename
	filename string
	// The file's latest modification time
	ModTime int64
}

// PGPMessage stores a PGP-encrypted message.
type PGPMessage struct {
	// KeyPacket references the PKESK and SKESK packets of the message
	KeyPacket []byte
	// DataPacket references the SEIPD or AEAD protected packet of the message
	DataPacket []byte
	// DetachedSignature stores the encrypted detached signature.
	// Nil when the signature is embedded in the data packet or not present.
	DetachedSignature []byte
}

type PGPMessageBuffer struct {
	key       *bytes.Buffer
	data      *bytes.Buffer
	signature *bytes.Buffer
}

// ---- GENERATORS -----

// NewFileMetadata creates literal metadata.
func NewFileMetadata(isUTF8 bool, filename string, modTime int64) *LiteralMetadata {
	return &LiteralMetadata{isUTF8: isUTF8, filename: filename, ModTime: modTime}
}

// NewMetadata creates new default literal metadata with utf-8 set to isUTF8.
func NewMetadata(isUTF8 bool) *LiteralMetadata {
	return &LiteralMetadata{isUTF8: isUTF8}
}

// NewPGPMessage generates a new PGPMessage from the unarmored binary data.
// Clones the data for go-mobile compatibility.
func NewPGPMessage(data []byte) *PGPMessage {
	return NewPGPMessageWithCloneFlag(data, true)
}

// NewPGPMessageWithCloneFlag generates a new PGPMessage from the unarmored binary data.
func NewPGPMessageWithCloneFlag(data []byte, doClone bool) *PGPMessage {
	packetData := data
	if doClone {
		packetData = clone(data)
	}
	pgpMessage := &PGPMessage{
		DataPacket: packetData,
	}
	pgpMessage, err := pgpMessage.splitMessage()
	if err != nil {
		// If there is an error in split treat the data as data packets.
		return &PGPMessage{
			DataPacket: packetData,
		}
	}
	return pgpMessage
}

// NewPGPMessageFromArmored generates a new PGPMessage from an armored string ready for decryption.
func NewPGPMessageFromArmored(armored string) (*PGPMessage, error) {
	encryptedIO, err := internal.Unarmor(armored)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in unarmoring message")
	}

	message, err := io.ReadAll(encryptedIO.Body)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in reading armored message")
	}
	pgpMessage := &PGPMessage{
		DataPacket: message,
	}
	pgpMessage, err = pgpMessage.splitMessage()
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in splitting message")
	}
	return pgpMessage, nil
}

// NewPGPSplitMessage generates a new PGPSplitMessage from the binary unarmored keypacket and datapacket.
// Clones the slices for go-mobile compatibility.
func NewPGPSplitMessage(keyPacket []byte, dataPacket []byte) *PGPMessage {
	return &PGPMessage{
		KeyPacket:  clone(keyPacket),
		DataPacket: clone(dataPacket),
	}
}

// NewPGPMessageBuffer creates a message buffer.
func NewPGPMessageBuffer() *PGPMessageBuffer {
	return &PGPMessageBuffer{
		key:       new(bytes.Buffer),
		data:      new(bytes.Buffer),
		signature: new(bytes.Buffer),
	}
}

// ---- MODEL METHODS -----

// Bytes returns the unarmored binary content of the message as a []byte.
func (msg *PGPMessage) Bytes() []byte {
	return append(msg.KeyPacket, msg.DataPacket...)
}

// NewReader returns a New io.Reader for the unarmored binary data of the
// message.
// Not supported on go-mobile clients.
func (msg *PGPMessage) NewReader() io.Reader {
	return bytes.NewReader(msg.Bytes())
}

// Armor returns the armored message as a string.
func (msg *PGPMessage) Armor() (string, error) {
	if msg.KeyPacket == nil {
		return "", errors.New("gopenpgp: missing key packets in pgp message")
	}
	return armor.ArmorPGPMessage(msg.Bytes())
}

// ArmorBytes returns the armored message as a string.
func (msg *PGPMessage) ArmorBytes() ([]byte, error) {
	if msg.KeyPacket == nil {
		return nil, errors.New("gopenpgp: missing key packets in pgp message")
	}
	return armor.ArmorPGPMessageBytes(msg.Bytes())
}

// ArmorWithCustomHeaders returns the armored message as a string, with
// the given headers. Empty parameters are omitted from the headers.
func (msg *PGPMessage) ArmorWithCustomHeaders(comment, version string) (string, error) {
	return armor.ArmorWithTypeAndCustomHeaders(msg.Bytes(), constants.PGPMessageHeader, version, comment)
}

// EncryptionKeyIDs Returns the key IDs of the keys to which the session key is encrypted.
// Not supported on go-mobile clients use msg.HexEncryptionKeyIDsJson() instead.
func (msg *PGPMessage) EncryptionKeyIDs() ([]uint64, bool) {
	packets := packet.NewReader(bytes.NewReader(msg.KeyPacket))
	var err error
	var ids []uint64
	var encryptedKey *packet.EncryptedKey
Loop:
	for {
		var p packet.Packet
		if p, err = packets.Next(); goerrors.Is(err, io.EOF) {
			break
		}
		switch p := p.(type) {
		case *packet.EncryptedKey:
			encryptedKey = p
			ids = append(ids, encryptedKey.KeyId)
		case *packet.SymmetricallyEncrypted,
			*packet.AEADEncrypted,
			*packet.Compressed,
			*packet.LiteralData:
			break Loop
		}
	}
	if len(ids) > 0 {
		return ids, true
	}
	return ids, false
}

// HexEncryptionKeyIDs returns the key IDs of the keys to which the session key is encrypted.
// Not supported on go-mobile clients use msg.HexEncryptionKeyIDsJson() instead.
func (msg *PGPMessage) HexEncryptionKeyIDs() ([]string, bool) {
	return hexKeyIDs(msg.EncryptionKeyIDs())
}

// HexEncryptionKeyIDsJson returns the key IDs of the keys to which the session key is encrypted as a JSON array.
// If an error occurs it returns nil.
// Helper function for go-mobile clients.
func (msg *PGPMessage) HexEncryptionKeyIDsJson() []byte {
	hexIds, ok := msg.HexEncryptionKeyIDs()
	if !ok {
		return nil
	}
	hexIdsJson, err := json.Marshal(hexIds)
	if err != nil {
		return nil
	}
	return hexIdsJson
}

// SignatureKeyIDs returns the key IDs of the keys to which the (readable) signature packets are encrypted to.
// Not supported on go-mobile clients use msg.HexSignatureKeyIDsJson() instead.
func (msg *PGPMessage) SignatureKeyIDs() ([]uint64, bool) {
	return SignatureKeyIDs(msg.DataPacket)
}

// HexSignatureKeyIDs returns the key IDs of the keys to which the session key is encrypted.
// Not supported on go-mobile clients use msg.HexSignatureKeyIDsJson() instead.
func (msg *PGPMessage) HexSignatureKeyIDs() ([]string, bool) {
	return hexKeyIDs(msg.SignatureKeyIDs())
}

// HexSignatureKeyIDsJson returns the key IDs of the keys to which the session key is encrypted as a JSON array.
// If an error occurs it returns nil.
// Helper function for go-mobile clients.
func (msg *PGPMessage) HexSignatureKeyIDsJson() []byte {
	sigHexSigIds, ok := msg.HexSignatureKeyIDs()
	if !ok {
		return nil
	}
	sigHexKeyIdsJSON, err := json.Marshal(sigHexSigIds)
	if err != nil {
		return nil
	}
	return sigHexKeyIdsJSON
}

// BinaryDataPacket returns the unarmored binary datapacket as a []byte.
func (msg *PGPMessage) BinaryDataPacket() []byte {
	return msg.DataPacket
}

// BinaryKeyPacket returns the unarmored binary keypacket as a []byte.
func (msg *PGPMessage) BinaryKeyPacket() []byte {
	return msg.KeyPacket
}

// EncryptedDetachedSignature returns the encrypted detached signature of this message
// as a PGPMessage where the data is the encrypted signature.
// If no detached signature is present in this message, it returns nil.
func (msg *PGPMessage) EncryptedDetachedSignature() *PGPMessage {
	if msg.DetachedSignature == nil {
		return nil
	}
	return &PGPMessage{
		KeyPacket:  msg.KeyPacket,
		DataPacket: msg.DetachedSignature,
	}
}

// splitMessage splits the message into key and data packet(s).
func (msg *PGPMessage) splitMessage() (*PGPMessage, error) {
	data := msg.DataPacket
	bytesReader := bytes.NewReader(data)
	packets := packet.NewReader(bytesReader)
	splitPoint := int64(0)
Loop:
	for {
		p, err := packets.Next()
		if goerrors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		switch p.(type) {
		case *packet.SymmetricKeyEncrypted, *packet.EncryptedKey:
			splitPoint = bytesReader.Size() - int64(bytesReader.Len())
		case *packet.SymmetricallyEncrypted, *packet.AEADEncrypted:
			break Loop
		}
	}
	return &PGPMessage{
		KeyPacket:  data[:splitPoint],
		DataPacket: data[splitPoint:],
	}, nil
}

// Filename returns the filename of the literal metadata.
func (msg *LiteralMetadata) Filename() string {
	if msg == nil {
		return ""
	}
	return msg.filename
}

// IsUtf8 returns whether the literal metadata is annotated with utf-8.
func (msg *LiteralMetadata) IsUtf8() bool {
	if msg == nil {
		return false
	}
	return msg.isUTF8
}

func (msg *LiteralMetadata) Time() int64 {
	if msg == nil {
		return 0
	}
	return msg.ModTime
}

// PGPMessageBuffer implements the PGPSplitWriter interface

func (mb *PGPMessageBuffer) Write(b []byte) (n int, err error) {
	return mb.data.Write(b)
}

// PGPMessage returns the PGPMessage extracted from the internal buffers.
func (mb *PGPMessageBuffer) PGPMessage() *PGPMessage {
	var detachedSignature []byte
	if mb.signature.Len() > 0 {
		detachedSignature = mb.signature.Bytes()
	}
	if mb.key.Len() == 0 {
		pgpMessage := NewPGPMessage(mb.data.Bytes())
		pgpMessage.DetachedSignature = detachedSignature
		return pgpMessage
	}
	return &PGPMessage{
		KeyPacket:         mb.key.Bytes(),
		DataPacket:        mb.data.Bytes(),
		DetachedSignature: detachedSignature,
	}
}

func (mb *PGPMessageBuffer) Keys() Writer {
	return mb.key
}

func (mb *PGPMessageBuffer) Signature() Writer {
	return mb.signature
}

// ---- UTILS -----

// IsPGPMessage checks if data if has armored PGP message format.
func IsPGPMessage(data string) bool {
	re := regexp.MustCompile("^-----BEGIN " + constants.PGPMessageHeader + "-----(?s:.+)-----END " +
		constants.PGPMessageHeader + "-----")
	return re.MatchString(data)
}

// SignatureKeyIDs returns the key identifiers of the keys that were used
// to create the signatures.
func SignatureKeyIDs(signature []byte) ([]uint64, bool) {
	packets := packet.NewReader(bytes.NewReader(signature))
	var err error
	var ids []uint64
	var onePassSignaturePacket *packet.OnePassSignature
	var signaturePacket *packet.Signature

Loop:
	for {
		var p packet.Packet
		if p, err = packets.Next(); goerrors.Is(err, io.EOF) {
			break
		}
		switch p := p.(type) {
		case *packet.OnePassSignature:
			onePassSignaturePacket = p
			ids = append(ids, onePassSignaturePacket.KeyId)
		case *packet.Signature:
			signaturePacket = p
			if signaturePacket.IssuerKeyId != nil {
				ids = append(ids, *signaturePacket.IssuerKeyId)
			}
		case *packet.SymmetricallyEncrypted,
			*packet.AEADEncrypted,
			*packet.Compressed,
			*packet.LiteralData:
			break Loop
		}
	}
	if len(ids) > 0 {
		return ids, true
	}
	return ids, false
}

// SignatureHexKeyIDs returns the key identifiers of the keys that were used
// to create the signatures in hexadecimal form.
func SignatureHexKeyIDs(signature []byte) ([]string, bool) {
	return hexKeyIDs(SignatureKeyIDs(signature))
}

func hexKeyIDs(keyIDs []uint64, ok bool) ([]string, bool) {
	hexIDs := make([]string, len(keyIDs))

	for i, id := range keyIDs {
		hexIDs[i] = keyIDToHex(id)
	}

	return hexIDs, ok
}

// clone returns a clone of the byte slice. Internal function used to make sure
// we don't retain a reference to external data.
func clone(input []byte) []byte {
	data := make([]byte, len(input))
	copy(data, input)
	return data
}
