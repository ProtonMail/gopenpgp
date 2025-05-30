// Package armor contains a set of helper methods for armoring and unarmoring
// data.
package armor

import (
	"bytes"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/internal"
)

// ArmorKey armors input as a public key.
func ArmorKey(input []byte) (string, error) {
	return ArmorWithType(input, constants.PublicKeyHeader)
}

// ArmorWriterWithType returns a io.WriteCloser which, when written to, writes
// armored data to w with the given armorType.
func ArmorWriterWithType(w io.Writer, armorType string) (io.WriteCloser, error) {
	return armor.EncodeWithChecksumOption(w, armorType, internal.ArmorHeaders, constants.ArmorChecksumEnabled)
}

// ArmorWriterWithTypeChecksum returns a io.WriteCloser which, when written to, writes
// armored data to w with the given armorType.
// The checksum determines if an armor checksum is written at the end.
func ArmorWriterWithTypeChecksum(w io.Writer, armorType string, checksum bool) (io.WriteCloser, error) {
	return armor.EncodeWithChecksumOption(w, armorType, internal.ArmorHeaders, checksum)
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
	return armor.EncodeWithChecksumOption(w, armorType, headers, constants.ArmorChecksumEnabled)
}

// ArmorWithType armors input with the given armorType.
func ArmorWithType(input []byte, armorType string) (string, error) {
	return ArmorWithTypeChecksum(input, armorType, constants.ArmorChecksumEnabled)
}

// ArmorWithTypeChecksum armors input with the given armorType.
// The checksum option determines if an armor checksum is written at the end.
func ArmorWithTypeChecksum(input []byte, armorType string, checksum bool) (string, error) {
	buffer, err := armorWithTypeAndHeaders(input, armorType, internal.ArmorHeaders, checksum)
	if err != nil {
		return "", err
	}
	return buffer.String(), err
}

// ArmorWithTypeBytes armors input with the given armorType.
func ArmorWithTypeBytes(input []byte, armorType string) ([]byte, error) {
	return ArmorWithTypeBytesChecksum(input, armorType, constants.ArmorChecksumEnabled)
}

// ArmorWithTypeBytesChecksum armors input with the given armorType and checksum option.
func ArmorWithTypeBytesChecksum(input []byte, armorType string, checksum bool) ([]byte, error) {
	buffer, err := armorWithTypeAndHeaders(input, armorType, internal.ArmorHeaders, checksum)
	if err != nil {
		return nil, err
	}
	return buffer.Bytes(), err
}

// ArmorWithTypeAndCustomHeaders armors input with the given armorType and
// headers.
func ArmorWithTypeAndCustomHeaders(input []byte, armorType, version, comment string) (string, error) {
	return ArmorWithTypeAndCustomHeadersChecksum(input, armorType, version, comment, constants.ArmorChecksumEnabled)
}

// ArmorWithTypeAndCustomHeadersChecksum armors input with the given armorType and
// headers and checksum option.
func ArmorWithTypeAndCustomHeadersChecksum(input []byte, armorType, version, comment string, checksum bool) (string, error) {
	headers := make(map[string]string)
	if version != "" {
		headers["Version"] = version
	}
	if comment != "" {
		headers["Comment"] = comment
	}
	buffer, err := armorWithTypeAndHeaders(input, armorType, headers, checksum)
	if err != nil {
		return "", err
	}
	return buffer.String(), err
}

// ArmorWithTypeAndCustomHeadersBytes armors input with the given armorType and
// headers.
func ArmorWithTypeAndCustomHeadersBytes(input []byte, armorType, version, comment string) ([]byte, error) {
	headers := make(map[string]string)
	if version != "" {
		headers["Version"] = version
	}
	if comment != "" {
		headers["Comment"] = comment
	}
	buffer, err := armorWithTypeAndHeaders(input, armorType, headers, constants.ArmorChecksumEnabled)
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
		return nil, fmt.Errorf("armor: unable to unarmor: %w", err)
	}
	return io.ReadAll(b.Body)
}

// UnarmorBytes unarmors an armored input into a byte array.
func UnarmorBytes(input []byte) ([]byte, error) {
	b, err := internal.UnarmorBytes(input)
	if err != nil {
		return nil, fmt.Errorf("armor: unable to unarmor: %w", err)
	}
	return io.ReadAll(b.Body)
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

func ArmorPGPMessageBytesChecksum(signature []byte, checksum bool) ([]byte, error) {
	return ArmorWithTypeBytesChecksum(signature, constants.PGPMessageHeader, checksum)
}

func ArmorPGPMessageChecksum(signature []byte, checksum bool) (string, error) {
	return ArmorWithTypeChecksum(signature, constants.PGPMessageHeader, checksum)
}

const armorPrefix = "-----BEGIN PGP"
const maxGarbageBytes = 128

// IsPGPArmored reads a prefix from the reader and checks
// if it is equal to a pgp armored message prefix.
// Returns an io.Reader that is reset to the state of the in reader,
// and a bool that indicates if there is a match.
// If reading from the reader fails, the returned bool is set to false.
func IsPGPArmored(in io.Reader) (io.Reader, bool) {
	buffer := make([]byte, len(armorPrefix)+maxGarbageBytes)
	n, _ := io.ReadFull(in, buffer)
	outReader := io.MultiReader(bytes.NewReader(buffer[:n]), in)
	if bytes.Contains(buffer[:n], []byte(armorPrefix)) {
		return outReader, true
	}
	return outReader, false
}

func armorWithTypeAndHeaders(input []byte, armorType string, headers map[string]string, writeChecksum bool) (*bytes.Buffer, error) {
	var b bytes.Buffer

	w, err := armor.EncodeWithChecksumOption(&b, armorType, headers, writeChecksum)

	if err != nil {
		return nil, fmt.Errorf("armor: unable to encode armoring: %w", err)
	}
	if _, err = w.Write(input); err != nil {
		return nil, fmt.Errorf("armor: unable to write armored to buffer: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, fmt.Errorf("armor: unable to close armor buffer: %w", err)
	}
	return &b, nil
}
