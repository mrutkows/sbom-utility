package utils

import (
	"fmt"

	"github.com/mrutkows/sbom-utility/log"
)

type MyFlags struct {
	// Not flags, but "main" package var copies
	Project    string
	Binary     string
	Version    string
	WorkingDir string
	ExecDir    string

	// persistent flags (common to all commands)
	Trace        bool // trace logging
	Debug        bool // debug logging
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
