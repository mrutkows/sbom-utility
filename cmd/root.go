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
	"fmt"
	"os"

	"github.com/mrutkows/sbom-utility/log"
	"github.com/mrutkows/sbom-utility/schema"
	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
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
)

const (
	DEFAULT_CONFIG = "config.json"
)

var rootCmd = &cobra.Command{
	Use:           fmt.Sprintf("%s [command] [flags]", utils.Flags.Project),
	SilenceErrors: false, // TODO: investigate if we should use
	SilenceUsage:  false, // TODO: investigate if we should use
	Short:         "Software Bill-of-Materials (SBOM) base utility.",
	Long:          "This utility serves as centralized command line interface into various Software Bill-of-Materials (SBOM) helper utilities.",
	RunE:          RootCmdImpl,
}

// initialize the module; primarily, initialize cobra
// NOTE: the "cmd" module is problematic as we actually are required to
// use init() to configure Cobra.  So if we want to debug that init(),
// that module actually has to create a logger simply for init() and the
// initConfig() callback.
func init() {
	// TODO: use LDFLAGS to turn on "TRACE" (and require creation of a Logger)
	// ONLY if needed to debug init() methods in the "cmd" package
	ProjectLogger = log.NewLogger(log.INFO)
	ProjectLogger.Enter()

	// Tell Cobra what our Cobra "init" call back method is
	cobra.OnInitialize(initConfig)

	// Declare top-level, persistent flags and where to place the post-parse values
	// TODO: move command help strings to (centralized) constants for better editing/translation across all files
	rootCmd.PersistentFlags().BoolVarP(&utils.Flags.Trace, FLAG_TRACE, FLAG_TRACE_SHORT, false, "enable trace logging")
	rootCmd.PersistentFlags().BoolVarP(&utils.Flags.Debug, FLAG_DEBUG, FLAG_DEBUG_SHORT, false, "enable debug logging")
	rootCmd.PersistentFlags().StringVarP(&utils.Flags.InputFile, FLAG_FILENAME_INPUT, FLAG_FILENAME_INPUT_SHORT, "", "input filename")
	rootCmd.PersistentFlags().StringVarP(&utils.Flags.OutputFile, FLAG_FILENAME_OUTPUT, FLAG_FILENAME_OUTPUT_SHORT, "", "output filename")

	ProjectLogger.Exit()
}

func initConfig() {
	ProjectLogger.Enter()

	// Update log level
	if utils.Flags.Debug {
		ProjectLogger.SetLevel(log.DEBUG)
	} else if utils.Flags.Trace {
		// debug level implies trace
		ProjectLogger.SetLevel(log.TRACE)
	}

	// Print global flags in debug mode
	flagInfo, err := log.FormatStruct("Flags", utils.Flags)
	if err != nil {
		ProjectLogger.Error(err.Error())
	} else {
		ProjectLogger.Debug(flagInfo)
	}

	// Print logger settings in debug mode
	logInfo, err2 := log.FormatStruct("Flags", utils.Flags)
	if err2 != nil {
		ProjectLogger.Error(err2.Error())
	} else {
		ProjectLogger.Debug(logInfo)
	}

	// Load application configuration files
	// i.e., Format/Schemas in this case
	errCfg := schema.LoadFormatBasedSchemas(DEFAULT_CONFIG)
	if errCfg != nil {
		ProjectLogger.Error(errCfg.Error())
	}

	ProjectLogger.Exit()
}

func RootCmdImpl(cmd *cobra.Command, args []string) error {
	ProjectLogger.Enter()
	// no commands (empty) passed; display help
	if len(args) == 0 {
		cmd.Help()
		os.Exit(0)
	}
	ProjectLogger.Exit()
	return nil
}

func Execute() {
	// instead of creating a dependency on the "main" module
	ProjectLogger.Enter()
	if err := rootCmd.Execute(); err != nil {
		// TODO: use log errors
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ProjectLogger.Exit()
}
