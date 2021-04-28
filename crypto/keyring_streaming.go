package crypto

import (
	"fmt"
	"io"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	"github.com/pkg/errors"
)

func IsEOF(err error) bool {
	return errors.Is(err, io.EOF)
}

type GoMobileReadResult struct {
	N     int
	IsEOF bool
	Data  []byte
}

func NewGoMobileReadResult(n int, eof bool, data []byte) *GoMobileReadResult {
	return &GoMobileReadResult{n, eof, data}
}

type GoMobileReader interface {
	Read(int) (*GoMobileReadResult, error)
}

type Writer interface {
	Write([]byte) (int, error)
}

type WriteCloser interface {
	Write([]byte) (int, error)
	Close() error
}

func (keyRing *KeyRing) EncryptStream(
	pgpMessageWriter Writer,
	isBinary bool,
	filename string,
	modTime int64,
	privateKey *KeyRing,
) (plainMessageWriter WriteCloser, err error) {
	config := &packet.Config{DefaultCipher: packet.CipherAES256, Time: getTimeGenerator()}
	var signEntity *openpgp.Entity

	if privateKey != nil && len(privateKey.entities) > 0 {
		var err error
		signEntity, err = privateKey.getSigningEntity()
		if err != nil {
			return nil, err
		}
	}

	hints := &openpgp.FileHints{
		IsBinary: isBinary,
		FileName: filename,
		ModTime:  time.Unix(modTime, 0),
	}

	if isBinary {
		plainMessageWriter, err = openpgp.Encrypt(pgpMessageWriter, keyRing.entities, signEntity, hints, config)
	} else {
		plainMessageWriter, err = openpgp.EncryptText(pgpMessageWriter, keyRing.entities, signEntity, hints, config)
	}
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in encrypting asymmetrically")
	}
	return plainMessageWriter, nil
}

type PlainMessageReader struct {
	Data     GoMobileReader
	TextType bool
	Filename string
	Time     uint32
}

type BridgingNative2GoReader struct {
	reader GoMobileReader
}

func (d *BridgingNative2GoReader) Read(b []byte) (int, error) {
	result, err := d.reader.Read(len(b))
	if err != nil {
		fmt.Printf("error while reading %v\n", err)
		return 0, err
	}
	n := result.N
	fmt.Printf("Read %d\n", n)
	if n > 0 {
		copy(b, result.Data[:n])
		fmt.Printf("Bytes %x\n", b[:n])
	}
	if result.IsEOF {
		fmt.Println("EOF")
		err = io.EOF
	}
	return n, err
}

type BridgingGo2NativeReader struct {
	reader io.Reader
}

func (d *BridgingGo2NativeReader) Read(max int) (*GoMobileReadResult, error) {
	b := make([]byte, max)
	n, err := d.reader.Read(b)
	result := &GoMobileReadResult{}
	if err != nil {
		if errors.Is(err, io.EOF) {
			fmt.Println("EOF")
			result.IsEOF = true
		} else {
			return nil, err
		}
	}
	result.N = n
	fmt.Printf("Read %d\n", n)
	if n > 0 {
		result.Data = b[:n]
		fmt.Printf("Bytes %x\n", b[:n])
	}
	return result, nil
}

func (keyRing *KeyRing) DecryptStream(
	message GoMobileReader, verifyKey *KeyRing, verifyTime int64,
) (plainMessage *PlainMessageReader, err error) {
	privKeyEntries := keyRing.entities
	var additionalEntries openpgp.EntityList

	if verifyKey != nil {
		additionalEntries = verifyKey.entities
	}

	if additionalEntries != nil {
		privKeyEntries = append(privKeyEntries, additionalEntries...)
	}

	config := &packet.Config{Time: getTimeGenerator()}

	messageDetails, err := openpgp.ReadMessage(&BridgingNative2GoReader{message}, privKeyEntries, nil, config)
	if err != nil {
		return nil, errors.Wrap(err, "gopenpgp: error in reading message")
	}

	if verifyKey != nil {
		processSignatureExpiration(messageDetails, verifyTime)
		err = verifyDetailsSignature(messageDetails, verifyKey)
	}

	return &PlainMessageReader{
		Data:     &BridgingGo2NativeReader{messageDetails.UnverifiedBody},
		TextType: !messageDetails.LiteralData.IsBinary,
		Filename: messageDetails.LiteralData.FileName,
		Time:     messageDetails.LiteralData.Time,
	}, err
}
