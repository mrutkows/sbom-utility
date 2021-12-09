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

// TODO: colorize log prefixes (e.g., warning=yellow, error=red)
// WARNING: Allow colorization to be a configurable option for
// human-readable targets (e.g., stdout, stderr, etc.) even a default (on);
// however, do NOT colorize if output is (file, network) stream
// See colors here: https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
var LevelNames = map[Level]string{
	DEBUG:   color.GreenString("debug"),
	TRACE:   color.CyanString("trace"),
	INFO:    color.WhiteString("info"),
	WARNING: color.HiYellowString("warning"),
	ERROR:   color.HiRedString("error"),
}

var DEFAULT_LEVEL = TRACE

type MyLog struct {
	logLevel      Level
	indentEnabled bool
	indentSpaces  uint
	indentCounter uint
	tagEnter      string
	tagExit       string
}

func NewLogger() MyLog {
	return MyLog{
		logLevel:      DEFAULT_LEVEL,
		indentEnabled: false,
		indentSpaces:  2,
		indentCounter: 0,
		tagEnter:      "ENTER",
		tagExit:       "EXIT",
	}
}

func (log *MyLog) SetLevel(level Level) {
	log.logLevel = level
}

func (log *MyLog) GetLevel() Level {
	return log.logLevel
}

func (log *MyLog) GetLevelName() string {
	return LevelNames[log.logLevel]
}

func (log *MyLog) SetIndentSpaces(spaces uint) {
	// Put some sensible limit on spaces
	if spaces > 8 {
		log.indentSpaces = spaces
	}
}

func (log MyLog) Trace(value interface{}) {
	log.dumpInterface(TRACE, "", value, STACK_SKIP)
}

func (log MyLog) Debug(value interface{}) {
	log.dumpInterface(DEBUG, "", value, STACK_SKIP)
}

func (log MyLog) Info(value interface{}) {
	log.dumpInterface(INFO, "", value, STACK_SKIP)
}

func (log MyLog) Warning(value interface{}) {
	log.dumpInterface(WARNING, "", value, STACK_SKIP)
}

// TODO: use fmt.fError ins some manner and/or os.Stderr
func (log MyLog) Error(value interface{}) {
	log.dumpInterface(ERROR, "", value, STACK_SKIP)
}

// Specialized function entry/exit trace
// TODO: make variadic and dump args
func (log MyLog) Enter() {
	// TODO: make variadic and dump args
	log.dumpInterface(TRACE, log.tagEnter, nil, STACK_SKIP)
}

// TODO: make variadic and dump return values
func (log MyLog) Exit(values ...interface{}) {

	sb := bytes.NewBufferString(log.tagExit)
	if len(values) > 0 {
		sb.WriteByte('(')
		for index, value := range values {
			fmt.Printf("value[%d] (%T): %+v\n", index, value, value)
			switch t := value.(type) {
			case int:
			case uint:
			case int32:
			case int64:
			case uint64:
				fmt.Println("Type is an integer:", t)
			case float32:
			case float64:
				fmt.Println("Type is a float:", t)
			case string:
				fmt.Println("Type is a string:", t)
			case nil:
				fmt.Println("Type is nil.")
			case bool:
				fmt.Println("Type is a bool:", t)
			default:
				fmt.Printf("Type is unknown!: %v\n", t)
			}

		}
		sb.WriteByte(')')
	}

	log.dumpInterface(TRACE, sb.String(), nil, STACK_SKIP)
}

// TODO: add error type to variadic method handling
func (log MyLog) ExitError(err error) {
	log.dumpInterface(TRACE, "EXIT", err, STACK_SKIP)
}

// compose log output using a bytebuffer for performance
func (log MyLog) dumpInterface(lvl Level, tag string, value interface{}, skip int) {

	// Do not recurse, but allow for debugging of this function directly
	// TODO: see if we can reuse format/pattern used below
	if log.logLevel == DEBUG {
		fmt.Printf("dumpInterface(): %s\n", log.DumpStruct("logger", log))
	}

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

func (log MyLog) DumpStruct(structName string, field interface{}) error {

	formattedStruct, err := FormatStruct(structName, field)
	if err != nil {
		return err
	}
	fmt.Print(formattedStruct)
	return nil
}

func (log MyLog) DumpArgs() {
	args := os.Args
	for i, a := range args {
		fmt.Printf("os.Arg[%d]: `%v`\n", i, a)
	}
}

func (log MyLog) DumpSeparator(sep byte, repeat int) error {
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
