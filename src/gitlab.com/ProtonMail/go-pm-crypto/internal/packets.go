package internal

import (
	"bytes"
	"golang.org/x/crypto/openpgp/packet"
	"gitlab.com/ProtonMail/go-pm-crypto/models"
	"io"
	"runtime"
		)

func SplitPackets(encryptedReader io.Reader, estimatedLength int, garbageCollector int) (*models.EncryptedSplit, error){
	var err error

	// For info on each, see: https://golang.org/pkg/runtime/#MemStats
	//kr *KeyRing, r io.Reader) (key *SymmetricKey, symEncryptedData []byte,
	packets := packet.NewReader(encryptedReader)

	outSplit := &models.EncryptedSplit{}
	gcCounter := 0

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
			// The code below is optimized to not
			var b bytes.Buffer
			// 2^16 is an estimation of the size difference between input and output, the size difference is most probably
			// 16 bytes at a maximum though.
			// We need to avoid triggering a grow from the system as this will allocate too much memory causing problems
			// in low-memory environments
			b.Grow(1 << 16 + estimatedLength)
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
				symEncryptedData[4] = 192+byte(actualLength>>8)
				symEncryptedData[5] = byte(actualLength)
				symEncryptedData = symEncryptedData[3:]
			} else {
				symEncryptedData[0] = byte(210)
				symEncryptedData[1] = byte(255)
				symEncryptedData[2] = byte(actualLength>>24)
				symEncryptedData[3] = byte(actualLength>>16)
				symEncryptedData[4] = byte(actualLength>>8)
				symEncryptedData[5] = byte(actualLength)
			}

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
