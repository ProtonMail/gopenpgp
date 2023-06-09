package crypto

import (
	"github.com/ProtonMail/go-crypto/v2/openpgp"
	"github.com/ProtonMail/gopenpgp/v3/constants"
	"github.com/pkg/errors"
)

type identity struct {
	name, comment, email string
}

type keyGenerationHandle struct {
	identities      []identity
	keyLifetimeSecs uint32
	profile         KeyGenerationProfile
	clock           Clock
}

// --- Default key generation handle to build from

func defaultKeyGenerationHandle(profile KeyGenerationProfile, clock Clock) *keyGenerationHandle {
	return &keyGenerationHandle{
		clock:   clock,
		profile: profile,
	}
}

// --- Implements PGPKeyGeneration interface

func (kgh *keyGenerationHandle) GenerateKey() (key *Key, err error) {
	return kgh.GenerateKeyWithSecurity(constants.StandardSecurity)
}

func (kgh *keyGenerationHandle) GenerateKeyWithSecurity(security constants.SecurityLevel) (key *Key, err error) {
	config := kgh.profile.KeyGenerationConfig(security)
	config.Time = NewConstantClock(kgh.clock().Unix())
	config.KeyLifetimeSecs = kgh.keyLifetimeSecs
	key = &Key{}

	if len(kgh.identities) == 0 {
		if config.V6() {
			key.entity, err = openpgp.NewEntityWithoutId(config)
		} else {
			return nil, errors.New("gopenpgp: non-v6 key requires a user id")
		}
	} else {
		if err = kgh.identities[0].valid(); err != nil {
			return
		}
		key.entity, err = openpgp.NewEntity(
			kgh.identities[0].name,
			kgh.identities[0].comment,
			kgh.identities[0].email,
			config,
		)
	}
	if err != nil {
		return nil, errors.Wrap(err, "gopengpp: error in creating new entity")
	}

	for id := 1; id < len(kgh.identities); id++ {
		if err = kgh.identities[id].valid(); err != nil {
			return
		}
		err = key.entity.AddUserId(
			kgh.identities[id].name,
			kgh.identities[id].comment,
			kgh.identities[id].email,
			config,
		)
		if err != nil {
			return nil, errors.Wrap(err, "gopengpp: error in adding user id")
		}
	}

	if key.entity.PrivateKey == nil {
		return nil, errors.New("gopenpgp: error in generating private key")
	}
	return
}

func (id identity) valid() error {
	if len(id.email) == 0 && len(id.name) == 0 {
		return errors.New("gopenpgp: neither name nor email set in user id")
	}
	return nil
}
