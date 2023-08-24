package helper

import (
	"encoding/hex"
	"testing"

	"github.com/ProtonMail/gopenpgp/v2/crypto"
)

const testQuickCheckSessionKey = `038c9cb9d408074e36bac22c6b90973082f86e5b01f38b787da3927000365a81`
const testQuickCheckSessionKeyAlg = "aes256"
const testQuickCheckDataPacket = `d2540152ab2518950f282d98d901eb93c00fb55a3bb30b3b517d6a356f57884bac6963060ebb167ffc3296e5e99ec058aeff5003a4784a0734a62861ae56d2921b9b790d50586cd21cad45e2d84ac93fb5d8af2ce6c5`

func TestCheckDecrypt(t *testing.T) {
	sessionKeyData, err := hex.DecodeString(testQuickCheckSessionKey)
	if err != nil {
		t.Error(err)
	}
	dataPacket, err := hex.DecodeString(testQuickCheckDataPacket)
	if err != nil {
		t.Error(err)
	}
	sessionKey := &crypto.SessionKey{
		Key:  sessionKeyData,
		Algo: testQuickCheckSessionKeyAlg,
	}
	ok, err := QuickCheckDecrypt(sessionKey, dataPacket[:22])
	if err != nil {
		t.Error(err)
	}
	if !ok {
		t.Error("should be able to decrypt")
	}

	sessionKey.Key[0] += 1
	ok, err = QuickCheckDecrypt(sessionKey, dataPacket[:22])
	if err != nil {
		t.Error(err)
	}
	if ok {
		t.Error("should no be able to decrypt")
	}
}
