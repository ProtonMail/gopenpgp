package constants

const (
	// Use no compression (default).
	NoCompression int8 = 0
	// Use compression defined by the pgp profile.
	DefaultCompression int8 = 1
	// Use ZIP compression.
	ZIPCompression int8 = 2
	// Use ZLIB compression.
	ZLIBCompression int8 = 3
)
