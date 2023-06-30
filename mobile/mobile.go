// Package mobile provides tools for mobile compatibility.
package mobile

import "runtime/debug"

// FreeOSMemory can be used to explicitly
// call the garbage collector and
// return the unused memory to the OS.
func FreeOSMemory() {
	debug.FreeOSMemory()
}
