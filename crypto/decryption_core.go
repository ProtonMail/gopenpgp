package crypto

import (
	"bytes"
	"errors"
	"fmt"
	"io"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/ProtonMail/gopenpgp/v3/internal"
)

type pgpSplitReader struct {
	encMessage, encSignature Reader
}

// pgpSplitReader implements the PGPSplitReader interface

func (mw *pgpSplitReader) Read(b []byte) (int, error) {
	return mw.encMessage.Read(b)
}

func (mw *pgpSplitReader) Signature() Reader {
	return mw.encSignature
}

func NewPGPSplitReader(pgpMessage Reader, pgpEncryptedSignature Reader) *pgpSplitReader {
	return &pgpSplitReader{
		encMessage:   pgpMessage,
		encSignature: pgpEncryptedSignature,
	}
}

// decryptStream decrypts the stream either with the secret keys or a password.
func (dh *decryptionHandle) decryptStream(encryptedMessage Reader) (plainMessage *VerifyDataReader, err error) {
	var entries openpgp.EntityList

	config := dh.decryptionConfig(dh.clock().Unix())
	if dh.DecryptionKeyRing != nil {
		entries = dh.DecryptionKeyRing.entities
	}

	if dh.VerifyKeyRing != nil {
		entries = append(entries, dh.VerifyKeyRing.entities...)
	}

	if dh.VerificationContext != nil {
		config.KnownNotations = map[string]bool{constants.SignatureContextName: true}
	}

	var messageDetails *openpgp.MessageDetails
	if dh.DecryptionKeyRing != nil {
		// Private key based decryption
		messageDetails, err = openpgp.ReadMessage(encryptedMessage, entries, nil, config)
		if err != nil {
			return nil, fmt.Errorf("gopenpgp: decrypting message with private keys failed: %w", err)
		}
	} else {
		// Password based decryption
		var foundPassword = false
		resetReader := internal.NewResetReader(encryptedMessage)
		for _, password := range dh.Passwords {
			prompt := createPasswordPrompt(password)
			messageDetails, err = openpgp.ReadMessage(resetReader, entries, prompt, config)
			if err == nil {
				foundPassword = true
				resetReader.DisableBuffering()
				break
			}
			if _, err := resetReader.Reset(); err != nil {
				// Should not happen.
				return nil, fmt.Errorf("gopenpgp: buffer reset failed: %w", err)
			}
		}
		if !foundPassword {
			// Parsing errors when reading the message are most likely caused by incorrect password, but we cannot know for sure
			return nil, errors.New("gopenpgp: error in reading password protected message: wrong password or malformed message")
		}
	}

	// Add utf8 sanitizer if signature has type packet.SigTypeText
	internalReader := messageDetails.UnverifiedBody
	if messageDetails.IsSigned &&
		!dh.DisableAutomaticTextSanitize &&
		len(messageDetails.SignatureCandidates) > 0 &&
		messageDetails.SignatureCandidates[len(messageDetails.SignatureCandidates)-1].SigType == packet.SigTypeText {
		// TODO: This currently assumes that only one type of signature
		// can be present.
		internalReader = internal.NewSanitizeReader(internalReader)
	}
	return &VerifyDataReader{
		messageDetails,
		internalReader,
		dh.VerifyKeyRing,
		config.Time().Unix(),
		dh.DisableVerifyTimeCheck,
		false,
		dh.VerificationContext,
	}, nil
}

func (dh *decryptionHandle) decryptStreamWithSession(dataPacketReader Reader) (plainMessage *VerifyDataReader, err error) {
	messageDetails, verifyTime, err := dh.decryptStreamWithSessionAndParse(dataPacketReader)
	if err != nil {
		return nil, fmt.Errorf("gopenpgp: error in reading message: %w", err)
	}

	// Add utf8 sanitizer if signature has type packet.SigTypeText
	internalReader := messageDetails.UnverifiedBody
	if messageDetails.IsSigned &&
		!dh.DisableAutomaticTextSanitize &&
		len(messageDetails.SignatureCandidates) > 0 &&
		messageDetails.SignatureCandidates[len(messageDetails.SignatureCandidates)-1].SigType == packet.SigTypeText {
		// TODO: This currently assumes that only one type of signature
		// can be present.
		internalReader = internal.NewSanitizeReader(internalReader)
	}
	return &VerifyDataReader{
		messageDetails,
		internalReader,
		dh.VerifyKeyRing,
		verifyTime,
		dh.DisableVerifyTimeCheck,
		false,
		dh.VerificationContext,
	}, err
}

func (dh *decryptionHandle) decryptStreamWithSessionAndParse(messageReader io.Reader) (*openpgp.MessageDetails, int64, error) {
	var keyring openpgp.EntityList
	var decrypted io.ReadCloser
	var selectedSessionKey *SessionKey
	var err error
	// Read symmetrically encrypted data packet
	for _, sessionKeyCandidate := range dh.SessionKeys {
		decrypted, err = decryptStreamWithSessionKey(sessionKeyCandidate, messageReader)
		if err == nil { // No error occurred
			selectedSessionKey = sessionKeyCandidate
			break
		}
	}
	if selectedSessionKey == nil {
		return nil, 0, fmt.Errorf("gopenpgp: unable to decrypt message with session key: %w", err)
	}

	config := dh.decryptionConfig(dh.clock().Unix())
	checkPacketSequence := false
	config.CheckPacketSequence = &checkPacketSequence

	if dh.VerificationContext != nil {
		config.KnownNotations = map[string]bool{constants.SignatureContextName: true}
	}

	// Push decrypted packet as literal packet and use openpgp's reader
	if dh.VerifyKeyRing != nil {
		keyring = append(keyring, dh.VerifyKeyRing.entities...)
	}
	if dh.DecryptionKeyRing != nil {
		keyring = append(keyring, dh.DecryptionKeyRing.entities...)
	}
	md, err := openpgp.ReadMessage(decrypted, keyring, nil, config)
	if err != nil {
		return nil, 0, fmt.Errorf("gopenpgp: unable to decode symmetric packet: %w", err)
	}
	md.SessionKey = selectedSessionKey.Key
	md.UnverifiedBody = checkReader{decrypted, md.UnverifiedBody}
	return md, config.Time().Unix(), nil
}

func decryptStreamWithSessionKey(sessionKey *SessionKey, messageReader io.Reader) (io.ReadCloser, error) {
	var decrypted io.ReadCloser
	// Read symmetrically encrypted data packet
Loop:
	for {
		packets := packet.NewReader(messageReader)
		p, err := packets.Next()
		if err != nil {
			return nil, fmt.Errorf("gopenpgp: unable to read symmetric packet: %w", err)
		}

		// Decrypt data packet
		switch p := p.(type) {
		case *packet.EncryptedKey, *packet.SymmetricKeyEncrypted:
			// Ignore potential key packets
			continue
		case *packet.SymmetricallyEncrypted, *packet.AEADEncrypted:
			if symPacket, ok := p.(*packet.SymmetricallyEncrypted); ok {
				if !symPacket.IntegrityProtected {
					return nil, errors.New("gopenpgp: message is not authenticated")
				}
			}
			var dc packet.CipherFunction
			if sessionKey.hasAlgorithm() {
				dc, err = sessionKey.GetCipherFunc()
				if err != nil {
					return nil, fmt.Errorf("gopenpgp: unable to decrypt with session key: %w", err)
				}
			}
			encryptedDataPacket, isDataPacket := p.(packet.EncryptedDataPacket)
			if !isDataPacket {
				return nil, fmt.Errorf("gopenpgp: unknown data packet: %w", err)
			}
			decrypted, err = encryptedDataPacket.Decrypt(dc, sessionKey.Key)
			if err != nil {
				return nil, fmt.Errorf("gopenpgp: unable to decrypt symmetric packet: %w", err)
			}
			break Loop
		default:
			return nil, errors.New("gopenpgp: invalid packet type")
		}
	}
	return decrypted, nil
}

func (dh *decryptionHandle) decryptStreamAndVerifyDetached(encryptedData, encryptedSignature Reader, isPlaintextSignature bool) (plainMessage *VerifyDataReader, err error) {
	verifyTime := dh.clock().Unix()
	var mdData *openpgp.MessageDetails
	signature := encryptedSignature
	// Decrypt both messages
	if len(dh.SessionKeys) > 0 {
		// Decrypt with session key.
		mdData, _, err = dh.decryptStreamWithSessionAndParse(encryptedData)
		if err != nil {
			return nil, fmt.Errorf("gopenpgp: error in reading data message: %w", err)
		}
		if !isPlaintextSignature {
			// Decrypting reader for the encrypted signature
			mdSig, _, err := dh.decryptStreamWithSessionAndParse(encryptedSignature)
			if err != nil {
				return nil, fmt.Errorf("gopenpgp: error in reading detached signature message: %w", err)
			}
			signature = mdSig.UnverifiedBody
		}
	} else {
		// Password or private keys
		config := dh.decryptionConfig(verifyTime)
		var entries openpgp.EntityList
		if dh.DecryptionKeyRing != nil {
			entries = append(entries, dh.DecryptionKeyRing.entities...)
		}
		// Decrypting reader for the encrypted data
		var selectedPassword []byte
		if len(dh.Passwords) > 0 {
			resetReader := internal.NewResetReader(encryptedData)
			for _, passwordCandidate := range dh.Passwords {
				prompt := createPasswordPrompt(passwordCandidate)
				mdData, err = openpgp.ReadMessage(resetReader, entries, prompt, config)
				if err == nil { // No error occurred
					selectedPassword = passwordCandidate
					resetReader.DisableBuffering()
					break
				}
				if _, err := resetReader.Reset(); err != nil {
					// Should not happen
					return nil, fmt.Errorf("gopenpgp: buffer reset failed: %w", err)
				}
			}
			if selectedPassword == nil {
				return nil, fmt.Errorf("gopenpgp: error in reading data message: no password matched: %w", err)
			}
		} else {
			mdData, err = openpgp.ReadMessage(encryptedData, entries, nil, config)
			if err != nil {
				return nil, fmt.Errorf("gopenpgp: error in reading data message: %w", err)
			}
		}

		if !isPlaintextSignature {
			// Decrypting reader for the encrypted signature
			prompt := createPasswordPrompt(selectedPassword)
			noCheckPacketSequence := false
			config.CheckPacketSequence = &noCheckPacketSequence
			mdSig, err := openpgp.ReadMessage(encryptedSignature, entries, prompt, config)
			if err != nil {
				return nil, fmt.Errorf("gopenpgp: error in reading detached signature message: %w", err)
			}
			signature = mdSig.UnverifiedBody
		}
	}

	config := dh.decryptionConfig(verifyTime)

	// Verifying reader that wraps the decryption readers to verify the signature
	sigVerifyReader, err := verifyingDetachedReader(
		mdData.UnverifiedBody,
		signature,
		dh.VerifyKeyRing,
		dh.VerificationContext,
		dh.DisableVerifyTimeCheck,
		dh.DisableAutomaticTextSanitize,
		config,
		NewConstantClock(verifyTime),
	)
	if err != nil {
		return nil, err
	}
	// Update message details with information from the data of the pgp message
	sigVerifyReader.details.LiteralData = mdData.LiteralData
	sigVerifyReader.details.SessionKey = mdData.SessionKey
	return sigVerifyReader, nil
}

func getSignaturePacket(sig []byte) (*packet.Signature, error) {
	p, err := packet.Read(bytes.NewReader(sig))
	if err != nil {
		return nil, err
	}
	sigPacket, ok := p.(*packet.Signature)
	if !ok {
		return nil, fmt.Errorf("gopenpgp: invalid signature packet: %w", err)
	}
	return sigPacket, nil
}

func createPasswordPrompt(password []byte) func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
	if password == nil {
		return nil
	}
	firstTimeCalled := true
	return func(keys []openpgp.Key, symmetric bool) ([]byte, error) {
		if firstTimeCalled {
			firstTimeCalled = false
			return password, nil
		}
		// Re-prompt still occurs if SKESK pasrsing fails (i.e. when decrypted cipher algo is invalid).
		// For most (but not all) cases, inputting a wrong passwords is expected to trigger this error.
		return nil, errors.New("gopenpgp: wrong password in symmetric decryption")
	}
}

func (dh *decryptionHandle) decryptionConfig(configTime int64) *packet.Config {
	config := dh.profile.EncryptionConfig()

	// Check intended recipients in signatures.
	checkIntendedRecipients := !dh.DisableIntendedRecipients
	config.CheckIntendedRecipients = &checkIntendedRecipients

	// Check for valid packet sequence
	checkPacketSequence := !dh.DisableStrictMessageParsing
	config.CheckPacketSequence = &checkPacketSequence

	// Allow message decryption of PGP messages with no integrity tag.
	config.InsecureAllowUnauthenticatedMessages = dh.InsecureDisableUnauthenticatedMessagesCheck

	// Allow message decryption with signature keys.
	if dh.InsecureAllowDecryptionWithSigningKeys {
		config.InsecureAllowDecryptionWithSigningKeys = dh.InsecureAllowDecryptionWithSigningKeys
	}

	// Should the session key be returned.
	config.CacheSessionKey = dh.RetrieveSessionKey

	// Set max decompression size if set.
	if dh.MaxDecompressedSize != 0 {
		config.MaxDecompressedMessageSize = &dh.MaxDecompressedSize
	}

	// Set time.
	config.Time = NewConstantClock(configTime)
	return config
}
