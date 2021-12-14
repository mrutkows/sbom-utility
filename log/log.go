package log

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/fatih/color"
)

type Level int

// Skip 2 on call stack
// i.e., skip public (Caller) method (e.g., "Trace()" and internal
// "dumpInterface()" function
const STACK_SKIP int = 2

// WARNING: some functional logic may assume incremental ordering of levels
const (
	ERROR   Level = iota // 0 - Always output errors (stop execution)
	WARNING              // 1 - Always output (keep executing)
	INFO                 // 2 - General processing information
	TRACE                // 3 - Also, output functional info. (signature, parameter); include UTC timestamps
	DEBUG                // 4 - Also, output internal logic and data (timestamps included)
)

// TODO: Allow colorization to be a configurable option.
// on (default): for human-readable targets (e.g., console);
// off: for (remote) logging targets (file, network) stream
// See colors here: https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
var LevelNames = map[Level]string{
	DEBUG:   color.GreenString("debug"),
	TRACE:   color.CyanString("trace"),
	INFO:    color.WhiteString("info"),
	WARNING: color.HiYellowString("warning"),
	ERROR:   color.HiRedString("error"),
}

var DEFAULT_LEVEL = INFO

type MiniLogger struct {
	logLevel      Level
	indentEnabled bool
	indentSpaces  uint
	indentCounter uint
	tagEnter      string
	tagExit       string
}

func NewDefaultLogger() *MiniLogger {
	return &MiniLogger{
		logLevel:      DEFAULT_LEVEL,
		indentEnabled: false,
		indentSpaces:  2,
		indentCounter: 0,
		tagEnter:      "ENTER",
		tagExit:       "EXIT",
	}
}

func NewLogger(level Level) *MiniLogger {
	newLogger := NewDefaultLogger()
	newLogger.SetLevel(level)
	return newLogger
}

func (log *MiniLogger) SetLevel(level Level) {
	log.logLevel = level
}

func (log *MiniLogger) GetLevel() Level {
	return log.logLevel
}

func (log *MiniLogger) GetLevelName() string {
	return LevelNames[log.logLevel]
}

func (log *MiniLogger) SetIndentSpaces(spaces uint) {
	// Put some sensible limit on spaces
	if spaces > 8 {
		log.indentSpaces = spaces
	}
}

func (log MiniLogger) Trace(value interface{}) {
	log.dumpInterface(TRACE, "", value, STACK_SKIP)
}

func (log MiniLogger) Debug(value interface{}) {
	log.dumpInterface(DEBUG, "", value, STACK_SKIP)
}

func (log MiniLogger) Info(value interface{}) {
	log.dumpInterface(INFO, "", value, STACK_SKIP)
}

func (log MiniLogger) Warning(value interface{}) {
	log.dumpInterface(WARNING, "", value, STACK_SKIP)
}

// TODO: use fmt.fError ins some manner and/or os.Stderr
func (log MiniLogger) Error(value interface{}) {
	log.dumpInterface(ERROR, "", value, STACK_SKIP)
}

// Specialized function entry/exit trace
// TODO: make variadic and dump args
func (log MiniLogger) Enter() {
	// TODO: make variadic and dump args
	log.dumpInterface(TRACE, log.tagEnter, nil, STACK_SKIP)
}

// exit and print returned values (typed)
func (log MiniLogger) Exit(values ...interface{}) {

	sb := bytes.NewBufferString(log.tagExit)
	if len(values) > 0 {
		sb.WriteByte('(')
		for index, value := range values {
			// TODO: if type is `error`, highlight/colorize (bright red)
			sb.WriteString(fmt.Sprintf("(%T):%+v", value, value))
			if (index + 1) < len(values) {
				sb.WriteString(", ")
			}

		}
		sb.WriteByte(')')
	}
	log.dumpInterface(TRACE, sb.String(), nil, STACK_SKIP)
}

// Note: currently, "dump" methods output directly to stdout (stderr)
// compose log output using a bytebuffer for performance
func (log MiniLogger) dumpInterface(lvl Level, tag string, value interface{}, skip int) {

	if lvl <= log.logLevel {
		// retrieve all the info we might need
		pc, fn, line, ok := runtime.Caller(skip)

		// TODO: create a logging package that can indent based upon stack size
		// Note: the "Callers()" method will not append() so allocate a large array
		// var mystack []uintptr = make([]uintptr, 10)
		// stacksize := runtime.Callers(0, mystack)
		//fmt.Printf("stacksize=%v\n", stacksize)

		// TODO: Provide means to order component output;
		// for example, to add Timestamp component first (on each line) before Level
		if ok {
			// Setup "string builder" and initialize with log-level prefix
			sb := bytes.NewBufferString(fmt.Sprintf("[%s] ", LevelNames[lvl]))

			// Append UTC timestamp if TRACE (or DEBUG) enabled
			if lvl == TRACE || lvl == DEBUG {
				// UTC time shows fractions of a second
				// TODO: add setting to show milli or micro seconds supported by "time" package
				tmp := time.Now().UTC().String()
				// create a (left) slice of the timestamp omitting the " +0000 UTC" portion
				//ts = fmt.Sprintf("[%s] ", tmp[:strings.Index(tmp, "+")-1])
				sb.WriteString(fmt.Sprintf("[%s] ", tmp[:strings.Index(tmp, "+")-1]))
			}

			// Append basic filename, line number, function name
			basicFile := fn[strings.LastIndex(fn, "/")+1:]
			function := runtime.FuncForPC(pc)
			// TODO: add logger flag to show full module paths (not just module.function)
			basicModFnName := function.Name()[strings.LastIndex(function.Name(), "/")+1:]

			sb.WriteString(fmt.Sprintf("%s(%d) %s()", basicFile, line, basicModFnName))

			// Append (optional) tag
			if tag != "" {
				sb.WriteString(fmt.Sprintf(": %s", tag))
			}

			// Append (optional) value
			if value != nil {
				sb.WriteString(fmt.Sprintf(": %+v", value))
			}
			// TODO: use a general output writer (set to stdout, stderr, or filestream)
			fmt.Println(sb.String())
		} else {
			os.Stderr.WriteString("Error: Unable to retrieve call stack. Exiting...")
			os.Exit(-2)
		}
	}
}

func (log MiniLogger) DumpString(value string) {
	fmt.Print(value)
}

func (log MiniLogger) DumpStruct(structName string, field interface{}) error {

	formattedStruct, err := FormatStruct(structName, field)
	if err != nil {
		return err
	}
	// TODO: print to output stream
	fmt.Print(formattedStruct)
	return nil
}

func (log MiniLogger) DumpArgs() {
	args := os.Args
	for i, a := range args {
		// TODO: print to output stream
		fmt.Printf("os.Arg[%d]: `%v`\n", i, a)
	}
}

func (log MiniLogger) DumpSeparator(sep byte, repeat int) error {
	if repeat <= 80 {
		sb := bytes.NewBufferString("")
		for i := 0; i < repeat; i++ {
			sb.WriteByte(sep)
		}
		fmt.Println(sb.String())
		return nil
	} else {
		return errors.New("invalid repeat length (>80)")
	}
}
