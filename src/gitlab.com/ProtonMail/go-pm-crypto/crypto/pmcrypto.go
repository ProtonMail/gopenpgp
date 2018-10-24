package crypto

import "time"

// PmCrypto structure to manage multiple address keys and user keys
// Called PGP crypto because it cannot have the same name as the package by gomobile's ridiculous rules.
type PmCrypto struct {
	//latestServerTime unix time cache
	latestServerTime int64
	latestClientTime time.Time
}

// //AddAddress add a new address to key ring
// //add a new address into addresses list
// func (pgp *PmCrypto) AddAddress(address *Address) (bool, error) {
// 	return true, errors.New("this is not implemented yet, will add this later")
// }

// //RemoveAddress remove address from the keyring
// //
// //#remove a exsit address from the list based on address id
// func (pgp *PmCrypto) RemoveAddress(addressID string) (bool, error) {
// 	return true, errors.New("this is not implemented yet, will add this later")
// }

// //CleanAddresses clear all addresses in keyring
// func (pgp *PmCrypto) CleanAddresses() (bool, error) {
// 	return true, errors.New("this is not implemented yet, will add this later")
// }

// //EncryptMessage encrypt message use address id
// func (pgp *PmCrypto) EncryptMessage(addressID string, plainText string, passphrase string, trim bool) (string, error) {
// 	return "", errors.New("this is not implemented yet, will add this later")
// }

// //DecryptMessage decrypt message, this will lookup all keys
// func (pgp *PmCrypto) DecryptMessage(encryptText string, passphras string) (string, error) {
// 	return "", errors.New("this is not implemented yet, will add this later")
// }
