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

package cmd

import (
	"flag"
	"fmt"
	"os"

	"github.com/mrutkows/sbom-utility/log"
	"github.com/mrutkows/sbom-utility/schema"
	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// !!! SECRET SAUCE !!!
// NOTE: Go test framework uses the "flags" package and all we need
// do is declare a new global for it to be recognized.
// USAGE: to set on command line and have it parsed, simply append
// it as follows: '--args -trace'
var TestLogLevelTrace = flag.Bool("trace", false, "")
var TestLogLevelError = flag.Bool("error", false, "")
var TestLogQuiet = flag.Bool("quiet", false, "")

const (
	ERROR_APPLICATION = 1
	ERROR_VALIDATION  = 2
)

var ProjectLogger *log.MiniLogger

const (
	FLAG_TRACE                 = "trace"
	FLAG_TRACE_SHORT           = "t"
	FLAG_DEBUG                 = "debug"
	FLAG_DEBUG_SHORT           = "d"
	FLAG_FILENAME_INPUT        = "input-file"
	FLAG_FILENAME_INPUT_SHORT  = "i"
	FLAG_FILENAME_OUTPUT       = "output-file"
	FLAG_FILENAME_OUTPUT_SHORT = "o"
	FLAG_QUIET_MODE            = "quiet"
	FLAG_QUIET_MODE_SHORT      = "q"
	FLAG_LOG_OUTPUT_INDENT     = "indent"
	FLAG_FILE_OUTPUT_FORMAT    = "format"
)

const (
	DEFAULT_CONFIG           = "config.json"
	DEFAULT_LICENSE_POLICIES = "license.json"
)

var rootCmd = &cobra.Command{
	Use:           fmt.Sprintf("%s [command] [flags]", utils.Flags.Project),
	SilenceErrors: false, // TODO: investigate if we should use
	SilenceUsage:  false, // TODO: investigate if we should use
	Short:         "Software Bill-of-Materials (SBOM) base utility.",
	Long:          "This utility serves as centralized command line interface into various Software Bill-of-Materials (SBOM) helper utilities.",
	RunE:          RootCmdImpl,
}

func getLogger() *log.MiniLogger {
	if ProjectLogger == nil {
		// TODO: use LDFLAGS to turn on "TRACE" (and require creation of a Logger)
		// ONLY if needed to debug init() methods in the "cmd" package
		ProjectLogger = log.NewLogger(log.ERROR)

		// Attempt to read in `--args` values such as `--trace`
		// Note: if they exist, quiet mode will be overridden
		// Default to ERROR level and, turn on "Quiet mode" for tests
		// This simplifies the test output to simply RUN/PASS|FAIL messages.
		ProjectLogger.InitLogLevelAndModeFromFlags()
	}
	return ProjectLogger
}

// initialize the module; primarily, initialize cobra
// NOTE: the "cmd" module is problematic as we actually are required to
// use init() to configure Cobra.  So if we want to debug that init(),
// that module actually has to create a logger simply for init() and the
// initConfig() callback.
func init() {
	getLogger().Enter()
	defer getLogger().Exit()

	// Tell Cobra what our Cobra "init" call back method is
	cobra.OnInitialize(initConfig)

	// Declare top-level, persistent flags and where to place the post-parse values
	// TODO: move command help strings to (centralized) constants for better editing/translation across all files
	rootCmd.PersistentFlags().BoolVarP(&utils.Flags.Trace, FLAG_TRACE, FLAG_TRACE_SHORT, false, "enable trace logging")
	rootCmd.PersistentFlags().BoolVarP(&utils.Flags.Debug, FLAG_DEBUG, FLAG_DEBUG_SHORT, false, "enable debug logging")
	rootCmd.PersistentFlags().StringVarP(&utils.Flags.InputFile, FLAG_FILENAME_INPUT, FLAG_FILENAME_INPUT_SHORT, "", "input filename")
	rootCmd.PersistentFlags().StringVarP(&utils.Flags.OutputFile, FLAG_FILENAME_OUTPUT, FLAG_FILENAME_OUTPUT_SHORT, "", "output filename")

	// NOTE: Although we check for the quiet mode flag in main; we track the flag
	// using Cobra framework in order to enable more comprehensive help
	// and take advantage of other features.
	rootCmd.PersistentFlags().BoolVarP(&utils.Flags.Quiet, FLAG_QUIET_MODE, FLAG_QUIET_MODE_SHORT, false, "enable quiet logging mode. Overrides other logging commands.")

	// Optionally, allow log callstack trace to be indented
	rootCmd.PersistentFlags().BoolVarP(&utils.Flags.LogOutputIndentCallstack, FLAG_LOG_OUTPUT_INDENT, "", false, "enable log indentation of functional callstack.")

	// Add commands
	rootCmd.AddCommand(NewCommandVersion())
	rootCmd.AddCommand(NewCommandSchema())
	rootCmd.AddCommand(NewCommandValidate())
	rootCmd.AddCommand(NewCommandQuery())
	licenseCmd := NewCommandLicense()

	licenseCmd.AddCommand(NewCommandList())
	licenseCmd.AddCommand(NewCommandPolicy())
	rootCmd.AddCommand(licenseCmd)
}

func initConfig() {
	getLogger().Enter()
	defer getLogger().Exit()

	// Update log level from command line flags (or simulated by test env.)
	if utils.Flags.Debug {
		getLogger().SetLevel(log.DEBUG)
	} else if utils.Flags.Trace {
		// debug level implies trace
		getLogger().SetLevel(log.TRACE)
	}

	// Other settings used by logger
	getLogger().SetQuietMode(utils.Flags.Quiet)
	getLogger().EnableIndent(utils.Flags.LogOutputIndentCallstack)

	// Print global flags in debug mode
	flagInfo, err := getLogger().FormatStructE(utils.Flags)
	if err != nil {
		getLogger().Error(err.Error())
	} else {
		getLogger().Debugf("%s: \n%s", "utils.Flags", flagInfo)
	}

	// NOTE: some commands operate just on JSON SBOM,
	// we leave the code below "in place" as we still want to validate any
	// input file as JSON SBOM document that matches a known format/version

	// Load application configuration file (i.e., primarily SBOM supported Formats/Schemas)
	// TODO: page fault "load" of data only when needed
	errCfg := schema.LoadFormatBasedSchemas(DEFAULT_CONFIG)
	if errCfg != nil {
		getLogger().Error(errCfg.Error())
		os.Exit(ERROR_APPLICATION)
	}

	// i.e., License approval policies
	// TODO: page fault "load" of data only when needed
	errPolicies := schema.LoadLicensePolicies(DEFAULT_LICENSE_POLICIES)
	if errPolicies != nil {
		getLogger().Error(errPolicies.Error())
		os.Exit(ERROR_APPLICATION)
	}

	// Hash policies for fast lookup
	// TODO: page fault hashmap only when needed
	hashPolicies(schema.LicensePolicyConfig.PolicyList)
}

func RootCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()

	// no commands (empty) passed; display help
	if len(args) == 0 {
		cmd.Help()
		os.Exit(ERROR_APPLICATION)
	}
	return nil
}

func Execute() {
	// instead of creating a dependency on the "main" module
	getLogger().Enter()
	defer getLogger().Exit()

	if err := rootCmd.Execute(); err != nil {
		// TODO: use log errors
		fmt.Fprintln(os.Stderr, err)
		os.Exit(ERROR_APPLICATION)
	}
}
