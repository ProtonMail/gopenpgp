package helper

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"io/ioutil"

	"github.com/ProtonMail/go-crypto/eax"
	"github.com/ProtonMail/go-crypto/ocb"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/ProtonMail/gopenpgp/v2/crypto"
	"github.com/pkg/errors"
	"golang.org/x/crypto/hkdf"
)

const aesBlockSize = 16
const copyChunkSize = 1024

func supported(cipher packet.CipherFunction) bool {
	switch cipher {
	case packet.CipherAES128, packet.CipherAES192, packet.CipherAES256:
		return true
	case packet.CipherCAST5, packet.Cipher3DES:
		return false
	}
	return false
}

func blockSize(cipher packet.CipherFunction) int {
	switch cipher {
	case packet.CipherAES128, packet.CipherAES192, packet.CipherAES256:
		return aesBlockSize
	case packet.CipherCAST5, packet.Cipher3DES:
		return 0
	}
	return 0
}

func blockCipher(cipher packet.CipherFunction, key []byte) (cipher.Block, error) {
	switch cipher {
	case packet.CipherAES128, packet.CipherAES192, packet.CipherAES256:
		return aes.NewCipher(key)
	case packet.CipherCAST5, packet.Cipher3DES:
		return nil, errors.New("gopenpgp: cipher not supported for quick check")
	}
	return nil, errors.New("gopenpgp: unknown cipher")
}

func aeadMode(mode packet.AEADMode, block cipher.Block) (alg cipher.AEAD, err error) {
	switch mode {
	case packet.AEADModeEAX:
		alg, err = eax.NewEAX(block)
	case packet.AEADModeOCB:
		alg, err = ocb.NewOCB(block)
	case packet.AEADModeGCM:
		alg, err = cipher.NewGCM(block)
	}
	if err != nil {
		return nil, err
	}
	return
}

func getSymmetricallyEncryptedAeadInstance(c packet.CipherFunction, mode packet.AEADMode, inputKey, salt, associatedData []byte) (aead cipher.AEAD, nonce []byte, err error) {
	hkdfReader := hkdf.New(sha256.New, inputKey, salt, associatedData)
	encryptionKey := make([]byte, c.KeySize())
	_, _ = io.ReadFull(hkdfReader, encryptionKey)
	nonce = make([]byte, mode.IvLength()-8)
	_, _ = io.ReadFull(hkdfReader, nonce)
	blockCipher, err := blockCipher(c, encryptionKey)
	if err != nil {
		return
	}
	aead, err = aeadMode(mode, blockCipher)
	return
}

func checkSEIPDv1Decrypt(
	sessionKey *crypto.SessionKey,
	prefixReader crypto.Reader,
) (bool, error) {
	cipher, err := sessionKey.GetCipherFunc()
	if err != nil {
		return false, errors.New("gopenpgp: cipher algorithm not found")
	}
	if !supported(cipher) {
		return false, errors.New("gopenpgp: cipher not supported for quick check")
	}

	blockSize := blockSize(cipher)
	encryptedData := make([]byte, blockSize+2)
	if _, err := io.ReadFull(prefixReader, encryptedData); err != nil {
		return false, errors.New("gopenpgp: prefix is too short to check")
	}

	blockCipher, err := blockCipher(cipher, sessionKey.Key)
	if err != nil {
		return false, errors.New("gopenpgp: failed to initialize the cipher")
	}
	packet.NewOCFBDecrypter(blockCipher, encryptedData, packet.OCFBNoResync)
	return encryptedData[blockSize-2] == encryptedData[blockSize] &&
		encryptedData[blockSize-1] == encryptedData[blockSize+1], nil
}

func checkSEIPDv2Decrypt(
	sessionKey *crypto.SessionKey,
	symPacket *packet.SymmetricallyEncrypted,
) (bool, error) {
	if !supported(symPacket.Cipher) {
		return false, errors.New("gopenpgp: cipher not supported for quick check")
	}
	buffer := new(bytes.Buffer)
	aeadTagLength := symPacket.Mode.TagLength()
	reader := symPacket.Contents
	var totalDataRead int64
	for {
		// Read up to copyChunkSize bytes into the buffer
		written, err := io.CopyN(buffer, reader, copyChunkSize-int64(buffer.Len()))
		totalDataRead += written
		// Discard all data from the buffer except last tag length bytes
		_, _ = io.CopyN(ioutil.Discard, buffer, int64(buffer.Len())-int64(aeadTagLength))
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return false, err
		}
	}
	totalDataRead -= int64(aeadTagLength)
	aeadChunkSize := int64(1 << (int64(symPacket.ChunkSizeByte) + 6))
	aeadChunkAndTagLength := aeadChunkSize + int64(aeadTagLength)
	numberOfChunks := totalDataRead / aeadChunkAndTagLength
	if totalDataRead%aeadChunkAndTagLength != 0 {
		numberOfChunks += 1
	}
	plaintextLength := totalDataRead - numberOfChunks*int64(aeadTagLength)

	var amountBytes [8]byte
	var index [8]byte
	binary.BigEndian.PutUint64(amountBytes[:], uint64(plaintextLength))
	binary.BigEndian.PutUint64(index[:], uint64(numberOfChunks))

	adata := []byte{
		0xD2,
		byte(symPacket.Version),
		byte(symPacket.Cipher),
		byte(symPacket.Mode),
		symPacket.ChunkSizeByte,
	}

	aead, nonce, err := getSymmetricallyEncryptedAeadInstance(symPacket.Cipher, symPacket.Mode, sessionKey.Key, symPacket.Salt[:], adata)
	if err != nil {
		return false, errors.New("gopenpgp: failed to instantiate aead cipher")
	}
	adata = append(adata, amountBytes[:]...)
	nonce = append(nonce, index[:]...)
	authenticationTag := buffer.Bytes()
	_, err = aead.Open(nil, nonce, authenticationTag, adata)
	return err == nil, nil
}

// QuickCheckDecryptReader checks with high probability if the provided session key
// can decrypt a data packet.
// For SEIPDv1 it only uses a 24 byte long prefix of the data packet.
// Thus, the function reads up to but not exactly 24 bytes from the prefixReader.
// For SEIPDv2 the function reads the whole data packet.
// NOTE: the function only works for data packets encrypted with AES.
func QuickCheckDecryptReader(sessionKey *crypto.SessionKey, dataPacketReader crypto.Reader) (bool, error) {
	packetParser := packet.NewReader(dataPacketReader)
	p, err := packetParser.Next()
	if err != nil {
		return false, errors.New("gopenpgp: failed to parse packet prefix")
	}
	if symPacket, ok := p.(*packet.SymmetricallyEncrypted); ok {
		switch symPacket.Version {
		case 1:
			return checkSEIPDv1Decrypt(sessionKey, dataPacketReader)
		case 2:
			return checkSEIPDv2Decrypt(sessionKey, symPacket)
		}
	}
	return false, errors.New("gopenpgp: no SEIPD packet found")
}

// QuickCheckDecrypt checks with high probability if the provided session key
// can decrypt the data packet.
// For SEIPDv1 it only uses a 24 byte long prefix of the data packet (dataPacket[:24]).
// For SEIPDv2 the function reads the whole data packet.
// NOTE: the function only works for data packets encrypted with AES.
func QuickCheckDecrypt(sessionKey *crypto.SessionKey, dataPacket []byte) (bool, error) {
	return QuickCheckDecryptReader(sessionKey, bytes.NewReader(dataPacket))
}
