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

package main

import (
	"fmt"
	"os"

	"github.com/mrutkows/sbom-utility/cmd"
	"github.com/mrutkows/sbom-utility/log"
	"github.com/mrutkows/sbom-utility/schema"
	"github.com/mrutkows/sbom-utility/utils"
)

// Struct used to hold tagged (release) build information
// Which is displayed by the `version` command.
// These values can be overwritten by `go build ${LDFLAGS}`
// for example, LDFLAGS=-ldflags "-X main.Version=${VERSION}
var (
	// public
	Project = "sbom-utility"
	Binary  = "unset"
	Version = "x.y.z"
	Logger  *log.MiniLogger
)

func init() {
	// TODO: allow default log level (for init() trace) to be set by LDFLAGS
	// For now, set to INFO here...
	// TODO: Perhaps add `-i` info flag to allow explicit control
	//Logger.SetLevel(log.INFO)
	// Set default log-level to only output basic informational execution feedback
	Logger = log.NewLogger(log.INFO)
	Logger.Trace(fmt.Sprintf("Logger (%T) created: with Level=`%v`", Logger, Logger.GetLevelName()))

	// Provide access to project logger to other modules
	cmd.ProjectLogger = Logger
	schema.ProjectLogger = Logger

	// Copy program package vars into command flags
	utils.Flags.Project = Project
	utils.Flags.Binary = Binary
	utils.Flags.Version = Version

	// Capture environment
	utils.Flags.WorkingDir, _ = os.Getwd()
	utils.Flags.ExecDir, _ = os.Executable()
}

func printWelcome() {
	echo := fmt.Sprintf("Welcome to the %s! Version `%s` (%s)\n", Project, Version, Binary)
	Logger.DumpString(echo)
	Logger.DumpSeparator('=', len(echo))
}

func main() {
	Logger.Enter()
	printWelcome()

	// Use Cobra convention and execute top-level command
	cmd.Execute()
	Logger.Exit()
}
