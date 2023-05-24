// Package armor contains a set of helper methods for armoring and unarmoring
// data.
package armor

import (
	"bytes"
	"io"
	"io/ioutil"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/internal"
	"github.com/pkg/errors"
)

// ArmorKey armors input as a public key.
func ArmorKey(input []byte) (string, error) {
	return ArmorWithType(input, constants.PublicKeyHeader)
}

// ArmorWriterWithType returns a io.WriteCloser which, when written to, writes
// armored data to w with the given armorType.
func ArmorWriterWithType(w io.Writer, armorType string) (io.WriteCloser, error) {
	return armor.Encode(w, armorType, internal.ArmorHeaders)
}

// ArmorWriterWithTypeAndCustomHeaders returns a io.WriteCloser,
// which armors input with the given armorType and headers.
func ArmorWriterWithTypeAndCustomHeaders(w io.Writer, armorType, version, comment string) (io.WriteCloser, error) {
	headers := make(map[string]string)
	if version != "" {
		headers["Version"] = version
	}
	if comment != "" {
		headers["Comment"] = comment
	}
	return armor.Encode(w, armorType, headers)
}

// ArmorWithType armors input with the given armorType.
func ArmorWithType(input []byte, armorType string) (string, error) {
	buffer, err := armorWithTypeAndHeaders(input, armorType, internal.ArmorHeaders)
	if err != nil {
		return "", err
	}
	return buffer.String(), err
}

// ArmorWithTypeBytes armors input with the given armorType.
func ArmorWithTypeBytes(input []byte, armorType string) ([]byte, error) {
	buffer, err := armorWithTypeAndHeaders(input, armorType, internal.ArmorHeaders)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), err
}

// ArmorWithTypeAndCustomHeaders armors input with the given armorType and
// headers.
func ArmorWithTypeAndCustomHeaders(input []byte, armorType, version, comment string) (string, error) {
	headers := make(map[string]string)
	if version != "" {
		headers["Version"] = version
	}
	if comment != "" {
		headers["Comment"] = comment
	}
	buffer, err := armorWithTypeAndHeaders(input, armorType, headers)
	if err != nil {
		return "", err
	}
	return buffer.String(), err
}

// ArmorWithTypeAndCustomHeaders armors input with the given armorType and
// headers.
func ArmorWithTypeAndCustomHeadersBytes(input []byte, armorType, version, comment string) ([]byte, error) {
	headers := make(map[string]string)
	if version != "" {
		headers["Version"] = version
	}
	if comment != "" {
		headers["Comment"] = comment
	}
	buffer, err := armorWithTypeAndHeaders(input, armorType, headers)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), err
}

// ArmorReader returns a io.Reader which, when read, reads
// unarmored data from in.
func ArmorReader(in io.Reader) (io.Reader, error) {
	block, err := armor.Decode(in)
	if err != nil {
		return nil, err
	}
	return block.Body, nil
}

// Unarmor unarmors an armored input into a byte array.
func Unarmor(input string) ([]byte, error) {
	b, err := internal.Unarmor(input)
	if err != nil {
		return nil, errors.Wrap(err, "gopengp: unable to unarmor")
	}
	return ioutil.ReadAll(b.Body)
}

// Unarmor unarmors an armored input into a byte array.
func UnarmorBytes(input []byte) ([]byte, error) {
	b, err := internal.UnarmorBytes(input)
	if err != nil {
		return nil, errors.Wrap(err, "gopengp: unable to unarmor")
	}
	return ioutil.ReadAll(b.Body)
}

func ArmorPGPSignatureBinary(signature []byte) ([]byte, error) {
	return ArmorWithTypeBytes(signature, constants.PGPSignatureHeader)
}

func ArmorPGPSignature(signature []byte) (string, error) {
	return ArmorWithType(signature, constants.PGPSignatureHeader)
}

func ArmorPGPMessageBytes(signature []byte) ([]byte, error) {
	return ArmorWithTypeBytes(signature, constants.PGPMessageHeader)
}

func ArmorPGPMessage(signature []byte) (string, error) {
	return ArmorWithType(signature, constants.PGPMessageHeader)
}

const armorPrefix = "-----BEGIN PGP"

// IsPGPArmored reads a prefix from the reader and checks
// if it is equal to a pgp armored message prefix.
// Returns an io.Reader that is reset to the state of the in reader,
// and a bool that indicates if there is a match.
// If reading from the reader fails, the returned bool is set to false.
func IsPGPArmored(in io.Reader) (io.Reader, bool) {
	buffer := make([]byte, len(armorPrefix))
	n, err := io.ReadFull(in, buffer)
	outReader := io.MultiReader(bytes.NewReader(buffer[:n]), in)
	if err != nil {
		return outReader, false
	}
	if bytes.Equal(buffer, []byte(armorPrefix)) {
		return outReader, true
	}
	return outReader, false
}

func armorWithTypeAndHeaders(input []byte, armorType string, headers map[string]string) (*bytes.Buffer, error) {
	var b bytes.Buffer

	w, err := armor.Encode(&b, armorType, headers)

	if err != nil {
		return nil, errors.Wrap(err, "gopengp: unable to encode armoring")
	}
	if _, err = w.Write(input); err != nil {
		return nil, errors.Wrap(err, "gopengp: unable to write armored to buffer")
	}
	if err := w.Close(); err != nil {
		return nil, errors.Wrap(err, "gopengp: unable to close armor buffer")
	}
	return &b, nil
}
