package utils

import (
	"fmt"

	"github.com/mrutkows/sbom-utility/log"
)

type MyFlags struct {
	// Not flags, but "main" package var copies
	Project string
	Binary  string
	Version string

	// persistent flags (common to all commands)
	Verbose      bool // Verbose logging
	InputFile    string
	InputFormat  string
	OutputFile   string
	OutputFormat string
}

var Flags MyFlags

// format and output the MyFlags struct as a string using Go's Stringer interface
func (flags *MyFlags) String() string {
	value, err := log.FormatStruct("utils.Flags", flags)

	if err != nil {
		return fmt.Sprintf("%s\n", err.Error())
	}
	return value
}
