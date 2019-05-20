package crypto

import (
	"bytes"
	"io"
	"io/ioutil"
	"runtime"
	"sync"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// AttachmentProcessor keeps track of the progress of encrypting an attachment
// (optimized for encrypting large files).
type AttachmentProcessor struct {
	w                *io.WriteCloser
	pipe             *io.PipeWriter
	done             sync.WaitGroup
	split            *PGPSplitMessage
	garbageCollector int
	err              error
}

// Process writes attachment data to be encrypted
func (ap *AttachmentProcessor) Process(plainData []byte) {
	if _, err := (*ap.w).Write(plainData); err != nil {
		panic(err)
	}
}

// Finish closes the attachment and returns the encrypted data
func (ap *AttachmentProcessor) Finish() (*PGPSplitMessage, error) {
	if ap.err != nil {
		return nil, ap.err
	}
	(*ap.w).Close()
	(*ap.pipe).Close()
	ap.done.Wait()
	if ap.garbageCollector > 0 {
		runtime.GC()
	}
	return ap.split, nil
}

// newAttachmentProcessor creates an AttachmentProcessor which can be used to encrypt
// a file. It takes an estimatedSize and fileName as hints about the file.
func (keyRing *KeyRing) newAttachmentProcessor(
	estimatedSize int, fileName string, garbageCollector int,
) (*AttachmentProcessor, error) {
	attachmentProc := &AttachmentProcessor{}
	// You could also add these one at a time if needed.
	attachmentProc.done.Add(1)
	attachmentProc.garbageCollector = garbageCollector

	hints := &openpgp.FileHints{
		FileName: fileName,
	}

	config := &packet.Config{
		DefaultCipher: packet.CipherAES256,
		Time:          pgp.getTimeGenerator(),
	}

	reader, writer := io.Pipe()

	go func() {
		defer attachmentProc.done.Done()
		ciphertext, _ := ioutil.ReadAll(reader)
		message := NewPGPMessage(ciphertext)
		split, splitError := message.SeparateKeyAndData(estimatedSize, garbageCollector)
		if attachmentProc.err != nil {
			attachmentProc.err = splitError
		}
		attachmentProc.split = split
	}()

	var ew io.WriteCloser
	var encryptErr error
	ew, encryptErr = openpgp.Encrypt(writer, keyRing.entities, nil, hints, config)
	if encryptErr != nil {
		return nil, encryptErr
	}
	attachmentProc.w = &ew
	attachmentProc.pipe = writer

	return attachmentProc, nil
}

// EncryptAttachment encrypts a file given a BinaryMessage and a fileName.
// Returns a PGPSplitMessage containing a session key packet and symmetrically encrypted data
func (keyRing *KeyRing) EncryptAttachment(message *BinaryMessage, fileName string) (*PGPSplitMessage, error) {
	ap, err := keyRing.newAttachmentProcessor(len(message.GetBinary()), fileName, -1)
	if err != nil {
		return nil, err
	}
	ap.Process(message.GetBinary())
	split, err := ap.Finish()
	if err != nil {
		return nil, err
	}
	return split, nil
}

// NewLowMemoryAttachmentProcessor creates an AttachmentProcessor which can be used
// to encrypt a file. It takes an estimatedSize and fileName as hints about the
// file. It is optimized for low-memory environments and collects garbage every
// megabyte.
func (keyRing *KeyRing) NewLowMemoryAttachmentProcessor(
	estimatedSize int, fileName string,
) (*AttachmentProcessor, error) {
	return keyRing.newAttachmentProcessor(estimatedSize, fileName, 1<<20)
}

// DecryptAttachment takes a PGPSplitMessage, containing a session key packet and symmetrically encrypted data
// and returns a decrypted BinaryMessage
func (keyRing *KeyRing) DecryptAttachment(message *PGPSplitMessage) (*BinaryMessage, error) {
	privKeyEntries := keyRing.entities

	keyReader := bytes.NewReader(message.GetKeyPacket())
	dataReader := bytes.NewReader(message.GetDataPacket())

	encryptedReader := io.MultiReader(keyReader, dataReader)

	config := &packet.Config{Time: pgp.getTimeGenerator()}

	md, err := openpgp.ReadMessage(encryptedReader, privKeyEntries, nil, config)
	if err != nil {
		return nil, err
	}

	decrypted := md.UnverifiedBody
	b, err := ioutil.ReadAll(decrypted)
	if err != nil {
		return nil, err
	}

	return NewBinaryMessage(b), nil
}
