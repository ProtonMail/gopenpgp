package crypto

import (
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"runtime"
	"sync"

	armorUtils "github.com/ProtonMail/go-pm-crypto/armor"
	"github.com/ProtonMail/go-pm-crypto/models"
	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// EncryptedSplit when encrypt attachment
type AttachmentProcessor struct {
	w                *io.WriteCloser
	pipe             *io.PipeWriter
	done             sync.WaitGroup
	split            *models.EncryptedSplit
	garbageCollector int
	err              error
}

// Process allows the attachment processor to write the encrypted attachment
func (ap *AttachmentProcessor) Process(plainData []byte) {
	(*ap.w).Write(plainData)
}

// Finish attachment process
func (ap *AttachmentProcessor) Finish() (*models.EncryptedSplit, error) {
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

// Encrypts attachment. Takes input data and key data in binary form
func (pm *PmCrypto) encryptAttachment(estimatedSize int, fileName string, publicKey *KeyRing, garbageCollector int) (*AttachmentProcessor, error) {
	attachmentProc := &AttachmentProcessor{}
	// you can also add these one at
	// a time if you need to
	attachmentProc.done.Add(1)
	attachmentProc.garbageCollector = garbageCollector

	hints := &openpgp.FileHints{
		FileName: fileName,
	}

	config := &packet.Config{
		DefaultCipher: packet.CipherAES256,
		Time:          pm.getTimeGenerator(),
	}

	reader, writer := io.Pipe()

	go func() {
		defer attachmentProc.done.Done()
		split, splitError := SeparateKeyAndData(nil, reader, estimatedSize, garbageCollector)
		if attachmentProc.err != nil {
			attachmentProc.err = splitError
		}
		split.Algo = "aes256"
		attachmentProc.split = split
	}()

	var ew io.WriteCloser
	var encryptErr error
	ew, encryptErr = openpgp.Encrypt(writer, publicKey.entities, nil, hints, config)
	if encryptErr != nil {
		return nil, encryptErr
	}
	attachmentProc.w = &ew
	attachmentProc.pipe = writer

	return attachmentProc, nil
}

// EncryptAttachment encrypts attachment. Takes input data and key data in binary form
func (pm *PmCrypto) EncryptAttachment(plainData []byte, fileName string, publicKey *KeyRing) (*models.EncryptedSplit, error) {
	ap, err := pm.encryptAttachment(len(plainData), fileName, publicKey, -1)
	if err != nil {
		return nil, err
	}
	ap.Process(plainData)
	split, err := ap.Finish()
	if err != nil {
		return nil, err
	}
	return split, nil

}

// EncryptAttachmentLowMemory ...
func (pm *PmCrypto) EncryptAttachmentLowMemory(estimatedSize int, fileName string, publicKey *KeyRing) (*AttachmentProcessor, error) {
	// Garbage collect every megabyte
	return pm.encryptAttachment(estimatedSize, fileName, publicKey, 1<<20)
}

// SplitArmor is a Helper method. Splits armored pgp session into key and packet data
func SplitArmor(encrypted string) (*models.EncryptedSplit, error) {
	var err error

	encryptedRaw, err := armorUtils.Unarmor(encrypted)
	if err != nil {
		return nil, err
	}

	encryptedReader := bytes.NewReader(encryptedRaw)

	return SeparateKeyAndData(nil, encryptedReader, len(encrypted), -1)
}

// Decrypt attachment. Takes input data and key data in binary form. privateKeys can contains more keys. passphrase is used to unlock keys
func (pm *PmCrypto) DecryptAttachment(keyPacket []byte, dataPacket []byte, kr *KeyRing, passphrase string) ([]byte, error) {

	privKeyEntries := kr.entities

	if err := kr.Unlock([]byte(passphrase)); err != nil {
		err = fmt.Errorf("pm-crypto: cannot decrypt attachment: %v", err)
		return nil, err
	}

	keyReader := bytes.NewReader(keyPacket)
	dataReader := bytes.NewReader(dataPacket)

	encryptedReader := io.MultiReader(keyReader, dataReader)

	config := &packet.Config{Time: pm.getTimeGenerator()}

	md, err := openpgp.ReadMessage(encryptedReader, privKeyEntries, nil, config)
	if err != nil {
		return nil, err
	}

	decrypted := md.UnverifiedBody
	b, err := ioutil.ReadAll(decrypted)
	if err != nil {
		return nil, err
	}

	return b, nil
}
