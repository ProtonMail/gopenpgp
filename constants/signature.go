package constants

// OpenPGP signature types.
// int8 type for go-mobile clients.
const (
	SigTypeBinary                  int8 = 0x00
	SigTypeText                    int8 = 0x01
	SigTypeGenericCert             int8 = 0x10
	SigTypePersonaCert             int8 = 0x11
	SigTypeCasualCert              int8 = 0x12
	SigTypePositiveCert            int8 = 0x13
	SigTypeSubkeyBinding           int8 = 0x18
	SigTypePrimaryKeyBinding       int8 = 0x19
	SigTypeDirectSignature         int8 = 0x1F
	SigTypeKeyRevocation           int8 = 0x20
	SigTypeSubkeyRevocation        int8 = 0x28
	SigTypeCertificationRevocation int8 = 0x30
)
