//go:build !ios
// +build !ios

package crypto

func sanitizeString(input string) string {
	return input
}
