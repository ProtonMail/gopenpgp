package crypto

import (
	"bytes"
	"io"
	"io/ioutil"

	"github.com/pkg/errors"
)

// EncryptStream is used to encrypt data as a Writer.
// It takes a writer for the encrypted data and returns a WriteCloser for the plaintext data
// If signKeyRing is not nil, it is used to do an embedded signature.
func (keyRing *KeyRing) EncryptStream(
	outputWriter Writer,
	plainMessageMetadata *PlainMessageMetadata,
	signKeyRing *KeyRing,
) (plainMessageWriter WriteCloser, err error) {
	return encryptStream(
		keyRing,
		nil,
		outputWriter,
		outputWriter,
		plainMessageMetadata,
		signKeyRing,
		false,
		nil,
		nil,
	)
}

// EncryptStreamWithContext is used to encrypt data as a Writer.
// It takes a writer for the encrypted data and returns a WriteCloser for the plaintext data
// If signKeyRing is not nil, it is used to do an embedded signature.
// * signingContext : (optional) a context for the embedded signature.
func (keyRing *KeyRing) EncryptStreamWithContext(
	pgpMessageWriter Writer,
	plainMessageMetadata *PlainMessageMetadata,
	signKeyRing *KeyRing,
	signingContext *SigningContext,
) (plainMessageWriter WriteCloser, err error) {
	return encryptStream(
		keyRing,
		nil,
		pgpMessageWriter,
		pgpMessageWriter,
		plainMessageMetadata,
		signKeyRing,
		false,
		signingContext,
		nil,
	)
}

// EncryptStreamWithCompression is used to encrypt data as a Writer.
// The plaintext data is compressed before being encrypted.
// It takes a writer for the encrypted data and returns a WriteCloser for the plaintext data
// If signKeyRing is not nil, it is used to do an embedded signature.
func (keyRing *KeyRing) EncryptStreamWithCompression(
	pgpMessageWriter Writer,
	plainMessageMetadata *PlainMessageMetadata,
	signKeyRing *KeyRing,
) (plainMessageWriter WriteCloser, err error) {
	return encryptStream(
		keyRing,
		nil,
		pgpMessageWriter,
		pgpMessageWriter,
		plainMessageMetadata,
		signKeyRing,
		true,
		nil,
		nil,
	)
}

// EncryptStreamWithContextAndCompression is used to encrypt data as a Writer.
// The plaintext data is compressed before being encrypted.
// It takes a writer for the encrypted data and returns a WriteCloser for the plaintext data
// If signKeyRing is not nil, it is used to do an embedded signature.
// * signingContext : (optional) a context for the embedded signature.
func (keyRing *KeyRing) EncryptStreamWithContextAndCompression(
	pgpMessageWriter Writer,
	plainMessageMetadata *PlainMessageMetadata,
	signKeyRing *KeyRing,
	signingContext *SigningContext,
) (plainMessageWriter WriteCloser, err error) {
	return encryptStream(
		keyRing,
		nil,
		pgpMessageWriter,
		pgpMessageWriter,
		plainMessageMetadata,
		signKeyRing,
		true,
		signingContext,
		nil,
	)
}

// EncryptSplitResult is used to wrap the encryption writecloser while storing the key packet.
type EncryptSplitResult struct {
	isClosed           bool
	keyPacketBuf       *bytes.Buffer
	keyPacket          []byte
	plainMessageWriter WriteCloser // The writer to writer plaintext data in.
}

func (res *EncryptSplitResult) Write(b []byte) (n int, err error) {
	return res.plainMessageWriter.Write(b)
}

func (res *EncryptSplitResult) Close() (err error) {
	err = res.plainMessageWriter.Close()
	if err != nil {
		return err
	}
	res.isClosed = true
	res.keyPacket = res.keyPacketBuf.Bytes()
	return nil
}

// GetKeyPacket returns the Public-Key Encrypted Session Key Packets (https://datatracker.ietf.org/doc/html/rfc4880#section-5.1).
// This can be retrieved only after the message has been fully written and the writer is closed.
func (res *EncryptSplitResult) GetKeyPacket() (keyPacket []byte, err error) {
	if !res.isClosed {
		return nil, errors.New("gopenpgp: can't access key packet until the message writer has been closed")
	}
	return res.keyPacket, nil
}

// EncryptSplitStream is used to encrypt data as a stream.
// It takes a writer for the Symmetrically Encrypted Data Packet
// (https://datatracker.ietf.org/doc/html/rfc4880#section-5.7)
// and returns a writer for the plaintext data and the key packet.
// If signKeyRing is not nil, it is used to do an embedded signature.
func (keyRing *KeyRing) EncryptSplitStream(
	dataPacketWriter Writer,
	plainMessageMetadata *PlainMessageMetadata,
	signKeyRing *KeyRing,
) (*EncryptSplitResult, error) {
	return encryptSplitStream(
		keyRing,
		nil,
		dataPacketWriter,
		plainMessageMetadata,
		signKeyRing,
		false,
		nil,
	)
}

// EncryptSplitStreamWithContext is used to encrypt data as a stream.
// It takes a writer for the Symmetrically Encrypted Data Packet
// (https://datatracker.ietf.org/doc/html/rfc4880#section-5.7)
// and returns a writer for the plaintext data and the key packet.
// If signKeyRing is not nil, it is used to do an embedded signature.
// * signingContext : (optional) a context for the embedded signature.
func (keyRing *KeyRing) EncryptSplitStreamWithContext(
	dataPacketWriter Writer,
	plainMessageMetadata *PlainMessageMetadata,
	signKeyRing *KeyRing,
	signingContext *SigningContext,
) (*EncryptSplitResult, error) {
	return encryptSplitStream(
		keyRing,
		nil,
		dataPacketWriter,
		plainMessageMetadata,
		signKeyRing,
		false,
		signingContext,
	)
}

// EncryptSplitStreamWithCompression is used to encrypt data as a stream.
// It takes a writer for the Symmetrically Encrypted Data Packet
// (https://datatracker.ietf.org/doc/html/rfc4880#section-5.7)
// and returns a writer for the plaintext data and the key packet.
// If signKeyRing is not nil, it is used to do an embedded signature.
func (keyRing *KeyRing) EncryptSplitStreamWithCompression(
	dataPacketWriter Writer,
	plainMessageMetadata *PlainMessageMetadata,
	signKeyRing *KeyRing,
) (*EncryptSplitResult, error) {
	return encryptSplitStream(
		keyRing,
		nil,
		dataPacketWriter,
		plainMessageMetadata,
		signKeyRing,
		true,
		nil,
	)
}

// EncryptSplitStreamWithContextAndCompression is used to encrypt data as a stream.
// It takes a writer for the Symmetrically Encrypted Data Packet
// (https://datatracker.ietf.org/doc/html/rfc4880#section-5.7)
// and returns a writer for the plaintext data and the key packet.
// If signKeyRing is not nil, it is used to do an embedded signature.
// * signingContext : (optional) a context for the embedded signature.
func (keyRing *KeyRing) EncryptSplitStreamWithContextAndCompression(
	dataPacketWriter Writer,
	plainMessageMetadata *PlainMessageMetadata,
	signKeyRing *KeyRing,
	signingContext *SigningContext,
) (*EncryptSplitResult, error) {
	return encryptSplitStream(
		keyRing,
		nil,
		dataPacketWriter,
		plainMessageMetadata,
		signKeyRing,
		true,
		signingContext,
	)
}

func encryptSplitStream(
	encryptionKeyRing *KeyRing,
	encryptionKeyRingHidden *KeyRing,
	dataPacketWriter Writer,
	plainMessageMetadata *PlainMessageMetadata,
	signKeyRing *KeyRing,
	compress bool,
	signingContext *SigningContext,
) (*EncryptSplitResult, error) {
	var keyPacketBuf bytes.Buffer
	plainMessageWriter, err := encryptStream(
		encryptionKeyRing,
		encryptionKeyRingHidden,
		&keyPacketBuf,
		dataPacketWriter,
		plainMessageMetadata,
		signKeyRing,
		compress,
		signingContext,
		nil,
	)
	if err != nil {
		return nil, err
	}

	return &EncryptSplitResult{
		keyPacketBuf:       &keyPacketBuf,
		plainMessageWriter: plainMessageWriter,
	}, nil
}

// DecryptStream is used to decrypt a pgp message as a Reader.
// It takes a reader for the message data
// and returns a PlainMessageReader for the plaintext data.
// If verifyKeyRing is not nil, PlainMessageReader.VerifySignature() will
// verify the embedded signature with the given key ring and verification time.
func (keyRing *KeyRing) DecryptStream(
	message Reader,
	verifyKeyRing *KeyRing,
	verifyTime int64,
) (plainMessage *PlainMessageReader, err error) {
	return decryptStream(
		keyRing,
		message,
		verifyKeyRing,
		verifyTime,
		nil,
		false,
	)
}

// DecryptStreamWithContext is used to decrypt a pgp message as a Reader.
// It takes a reader for the message data
// and returns a PlainMessageReader for the plaintext data.
// If verifyKeyRing is not nil, PlainMessageReader.VerifySignature() will
// verify the embedded signature with the given key ring and verification time.
// * verificationContext (optional): context for the signature verification.
func (keyRing *KeyRing) DecryptStreamWithContext(
	message Reader,
	verifyKeyRing *KeyRing,
	verifyTime int64,
	verificationContext *VerificationContext,
) (plainMessage *PlainMessageReader, err error) {
	return decryptStream(
		keyRing,
		message,
		verifyKeyRing,
		verifyTime,
		verificationContext,
		false,
	)
}

// DecryptSplitStream is used to decrypt a split pgp message as a Reader.
// It takes a key packet and a reader for the data packet
// and returns a PlainMessageReader for the plaintext data.
// If verifyKeyRing is not nil, PlainMessageReader.VerifySignature() will
// verify the embedded signature with the given key ring and verification time.
func (keyRing *KeyRing) DecryptSplitStream(
	keypacket []byte,
	dataPacketReader Reader,
	verifyKeyRing *KeyRing, verifyTime int64,
) (plainMessage *PlainMessageReader, err error) {
	messageReader := io.MultiReader(
		bytes.NewReader(keypacket),
		dataPacketReader,
	)
	return keyRing.DecryptStream(
		messageReader,
		verifyKeyRing,
		verifyTime,
	)
}

// DecryptSplitStreamWithContext is used to decrypt a split pgp message as a Reader.
// It takes a key packet and a reader for the data packet
// and returns a PlainMessageReader for the plaintext data.
// If verifyKeyRing is not nil, PlainMessageReader.VerifySignature() will
// verify the embedded signature with the given key ring and verification time.
// * verificationContext (optional): context for the signature verification.
func (keyRing *KeyRing) DecryptSplitStreamWithContext(
	keypacket []byte,
	dataPacketReader Reader,
	verifyKeyRing *KeyRing, verifyTime int64,
	verificationContext *VerificationContext,
) (plainMessage *PlainMessageReader, err error) {
	messageReader := io.MultiReader(
		bytes.NewReader(keypacket),
		dataPacketReader,
	)
	return keyRing.DecryptStreamWithContext(
		messageReader,
		verifyKeyRing,
		verifyTime,
		verificationContext,
	)
}

// SignDetachedStream generates and returns a PGPSignature for a given message Reader.
func (keyRing *KeyRing) SignDetachedStream(message Reader) (*PGPSignature, error) {
	return keyRing.SignDetachedStreamWithContext(message, nil)
}

// SignDetachedStreamWithContext generates and returns a PGPSignature for a given message Reader.
// If a context is provided, it is added to the signature as notation data
// with the name set in `constants.SignatureContextName`.
func (keyRing *KeyRing) SignDetachedStreamWithContext(message Reader, context *SigningContext) (*PGPSignature, error) {
	return signMessageDetached(
		keyRing,
		message,
		true,
		context,
	)
}

// VerifyDetachedStream verifies a message reader with a detached PGPSignature
// and returns a SignatureVerificationError if fails.
func (keyRing *KeyRing) VerifyDetachedStream(
	message Reader,
	signature *PGPSignature,
	verifyTime int64,
) error {
	_, err := verifySignature(
		keyRing.entities,
		message,
		signature.GetBinary(),
		verifyTime,
		nil,
	)
	return err
}

// VerifyDetachedStreamWithContext verifies a message reader with a detached PGPSignature
// and returns a SignatureVerificationError if fails.
// If a context is provided, it verifies that the signature is valid in the given context, using
// the signature notations.
func (keyRing *KeyRing) VerifyDetachedStreamWithContext(
	message Reader,
	signature *PGPSignature,
	verifyTime int64,
	verificationContext *VerificationContext,
) error {
	_, err := verifySignature(
		keyRing.entities,
		message,
		signature.GetBinary(),
		verifyTime,
		verificationContext,
	)
	return err
}

// SignDetachedEncryptedStream generates and returns a PGPMessage
// containing an encrypted detached signature for a given message Reader.
func (keyRing *KeyRing) SignDetachedEncryptedStream(
	message Reader,
	encryptionKeyRing *KeyRing,
) (encryptedSignature *PGPMessage, err error) {
	if encryptionKeyRing == nil {
		return nil, errors.New("gopenpgp: no encryption key ring provided")
	}
	signature, err := keyRing.SignDetachedStream(message)
	if err != nil {
		return nil, err
	}
	plainMessage := NewPlainMessage(signature.GetBinary())
	encryptedSignature, err = encryptionKeyRing.Encrypt(plainMessage, nil)
	return
}

// VerifyDetachedEncryptedStream verifies a PlainMessage
// with a PGPMessage containing an encrypted detached signature
// and returns a SignatureVerificationError if fails.
func (keyRing *KeyRing) VerifyDetachedEncryptedStream(
	message Reader,
	encryptedSignature *PGPMessage,
	decryptionKeyRing *KeyRing,
	verifyTime int64,
) error {
	if decryptionKeyRing == nil {
		return errors.New("gopenpgp: no decryption key ring provided")
	}
	plainMessage, err := decryptionKeyRing.Decrypt(encryptedSignature, nil, 0)
	if err != nil {
		return err
	}
	signature := NewPGPSignature(plainMessage.GetBinary())
	return keyRing.VerifyDetachedStream(message, signature, verifyTime)
}

// Core for decryption+verification (non streaming) functions.
func asymmetricDecrypt(
	encryptedIO io.Reader,
	privateKey *KeyRing,
	verifyKey *KeyRing,
	verifyTime int64,
	verificationContext *VerificationContext,
) (message *PlainMessage, err error) {
	messageDetails, err := asymmetricDecryptStream(
		encryptedIO,
		privateKey,
		verifyKey,
		verifyTime,
		verificationContext,
		false,
	)
	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(messageDetails.UnverifiedBody)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in reading message body")
	}

	if verifyKey != nil {
		processSignatureExpiration(messageDetails, verifyTime)
		err = verifyDetailsSignature(messageDetails, verifyKey, verificationContext)
	}

	return &PlainMessage{
		Data: body,
		PlainMessageMetadata: PlainMessageMetadata{
			IsUTF8:   messageDetails.LiteralData.IsUTF8,
			Filename: messageDetails.LiteralData.FileName,
			ModTime:  int64(messageDetails.LiteralData.Time),
		},
	}, err
}
