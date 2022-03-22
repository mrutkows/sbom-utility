/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

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

const MAX_INDENT uint = 8

// WARNING: some functional logic may assume incremental ordering of levels
const (
	ERROR   Level = iota // 0 - Always output errors (stop execution)
	WARNING              // 1 - Always output warnings (continue executing)
	INFO                 // 2 - General processing information (processing milestones)
	TRACE                // 3 - In addition to INFO, output functional info. (signature, parameter)
	DEBUG                // 4 - In addition to TRACE, output internal logic and intra-functional data
)

// TODO: Allow colorization to be a configurable option.
// on (default): for human-readable targets (e.g., console);
// off: for (remote) logging targets (file, network) stream
// See colors here: https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
var LevelNames = map[Level]string{
	DEBUG:   color.GreenString("DEBUG"),
	TRACE:   color.CyanString("TRACE"),
	INFO:    color.WhiteString("INFO"),
	WARNING: color.HiYellowString("WARN"),
	ERROR:   color.HiRedString("ERROR"),
}

var DEFAULT_LEVEL = INFO

type MiniLogger struct {
	logLevel      Level
	indentEnabled bool
	indentSpaces  uint
	indentCounter uint
	tagEnter      string
	tagExit       string
	quietMode     bool
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

func (log *MiniLogger) SetQuietMode(on bool) {
	log.quietMode = on
}

func (log *MiniLogger) QuietModeOn() bool {
	return log.quietMode
}

func (log *MiniLogger) GetLevelName() string {
	return LevelNames[log.logLevel]
}

func (log *MiniLogger) SetIndentSpaces(spaces uint) {
	// Put some sensible limit on spaces
	if spaces < MAX_INDENT {
		log.indentSpaces = spaces
	}
}

// Helper method to check for and set typical log-related flags
// NOTE: Assumes these do not collide with existing flags set by importing application
func (log *MiniLogger) InitLogLevelAndModeFromFlags(defaultLevel Level) Level {

	// Pre-set the requested default level
	log.SetLevel(defaultLevel)

	// Check for log-related flags (anywhere) and apply to logger
	// as early as possible (before customary Cobra flag formalization)
	// NOTE: the last log-level flag found, in order of appearance "wins"
	for _, arg := range os.Args[1:] {
		if arg == "-q" || arg == "--quiet" {
			// Quiet mode is an override concept
			// continue to process other log-level flags
			log.SetQuietMode(true)
		} else if arg == "-d" || arg == "--debug" {
			log.SetLevel(DEBUG)
		} else if arg == "-t" || arg == "--trace" {
			log.SetLevel(TRACE)
		}
	}

	return log.GetLevel()
}

func (log MiniLogger) Trace(value interface{}) {
	log.dumpInterface(TRACE, "", value, STACK_SKIP)
}

func (log MiniLogger) Tracef(format string, value ...interface{}) {
	message := fmt.Sprintf(format, value...)
	log.dumpInterface(TRACE, "", message, STACK_SKIP)
}

func (log MiniLogger) Debug(value interface{}) {
	log.dumpInterface(DEBUG, "", value, STACK_SKIP)
}

func (log MiniLogger) Debugf(format string, value ...interface{}) {
	message := fmt.Sprintf(format, value...)
	log.dumpInterface(DEBUG, "", message, STACK_SKIP)
}

func (log MiniLogger) Info(value interface{}) {
	log.dumpInterface(INFO, "", value, STACK_SKIP)
}

func (log MiniLogger) Infof(format string, value ...interface{}) {
	message := fmt.Sprintf(format, value...)
	log.dumpInterface(INFO, "", message, STACK_SKIP)
}

func (log MiniLogger) Warning(value interface{}) {
	log.dumpInterface(WARNING, "", value, STACK_SKIP)
}

func (log MiniLogger) Warningf(format string, value ...interface{}) {
	message := fmt.Sprintf(format, value...)
	log.dumpInterface(WARNING, "", message, STACK_SKIP)
}

// TODO: use fmt.fError ins some manner and/or os.Stderr
func (log MiniLogger) Error(value interface{}) {
	log.dumpInterface(ERROR, "", value, STACK_SKIP)
}

func (log MiniLogger) Errorf(format string, value ...interface{}) error {
	err := fmt.Errorf(format, value...)
	log.dumpInterface(ERROR, "", err, STACK_SKIP)
	return err
}

// Specialized function entry/exit trace
// Note: can pass in "args[]" or params as needed to have a single logging line
func (log MiniLogger) Enter(values ...interface{}) {

	sb := bytes.NewBufferString(log.tagEnter)
	if len(values) > 0 {
		sb.WriteByte('(')
		for index, value := range values {
			sb.WriteString(fmt.Sprintf("(%T):%+v", value, value))
			if (index + 1) < len(values) {
				sb.WriteString(", ")
			}

		}
		sb.WriteByte(')')
	}
	log.dumpInterface(TRACE, sb.String(), nil, STACK_SKIP)
}

// exit and print returned values (typed)
// Note: can function "returns" as needed to have a single logging line
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
// Note: we comment out any "self-logging" or 'debug" for performance for release builds
// compose log output using a bytebuffer for performance
func (log MiniLogger) dumpInterface(lvl Level, tag string, value interface{}, skip int) {

	// Check for quiet mode enabled;
	// if so, suppress any logging that is not an error
	if log.quietMode { // && log.logLevel != ERROR {
		return
	}

	// Only (prepare to) output if intended log level is less than
	// the current globally set log level
	if lvl <= log.logLevel {
		// TODO: Support indentation based upon stack size
		// Note: the "Callers()" method will not append() so allocate a large array
		// var mystack []uintptr = make([]uintptr, 10)
		// stacksize := runtime.Callers(0, mystack)
		//fmt.Printf("stacksize=%v\n", stacksize)

		// retrieve all the info we might need
		pc, fn, line, ok := runtime.Caller(skip)

		// TODO: Provide means to order component output;
		// for example, to add Timestamp component first (on each line) before Level
		if ok {
			// Setup "string builder" and initialize with log-level prefix
			sb := bytes.NewBufferString(fmt.Sprintf("[%s] ", LevelNames[lvl]))

			// Append UTC timestamp if level is TRACE or DEBUG
			if lvl == TRACE || lvl == DEBUG {

				// UTC time shows fractions of a second
				// TODO: add setting to show milli or micro seconds supported by "time" package
				tmp := time.Now().UTC().String()
				// create a (left) slice of the timestamp omitting the " +0000 UTC" portion
				//ts = fmt.Sprintf("[%s] ", tmp[:strings.Index(tmp, "+")-1])
				sb.WriteString(fmt.Sprintf("[%s] ", tmp[:strings.Index(tmp, "+")-1]))
			}

			// Append calling callstack/function information
			// for log levels used for developer problem determination
			if lvl == TRACE || lvl == DEBUG || lvl == ERROR {
				// Append basic filename, line number, function name
				basicFile := fn[strings.LastIndex(fn, "/")+1:]
				sb.WriteString(fmt.Sprintf("%s(%d) ", basicFile, line))

				// TODO: add logger flag to show full module paths (not just module.function)\
				function := runtime.FuncForPC(pc)
				basicModFnName := function.Name()[strings.LastIndex(function.Name(), "/")+1:]
				sb.WriteString(fmt.Sprintf("%s()", basicModFnName))

				// Append (optional) tag
				if tag != "" {
					sb.WriteString(fmt.Sprintf(": %s: ", tag))
				}

			}

			// Append (optional) value
			if value != nil {
				sb.WriteString(fmt.Sprintf("%+v", value))
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

func (log MiniLogger) DumpSeparator(sep byte, repeat int) (string, error) {
	if repeat <= 80 {
		sb := bytes.NewBufferString("")
		for i := 0; i < repeat; i++ {
			sb.WriteByte(sep)
		}
		fmt.Println(sb.String())
		return sb.String(), nil
	} else {
		return "", errors.New("invalid repeat length (>80)")
	}
}
