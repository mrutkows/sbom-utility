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
	"os"
	"strings"

	"github.com/mrutkows/sbom-utility/log"
	"github.com/mrutkows/sbom-utility/schema"
	"github.com/mrutkows/sbom-utility/utils"
)

func initTestInfra() {
	// Turn on "Quiet mode" for tests
	// This simplifies the output to RUN/PASS|FAIL messages.
	// NOTE: "go test" utilizes the Go "flags" package and allows
	// test packages to declare additional command line arguments
	// which can be used to set log/trace levels (e.g., `--args -trace).
	// The values for these variables are only avail. after init()
	// processing is completed.
	getLogger().SetQuietMode(true)
	// Set default level to error, when quiet mode turned off
	getLogger().SetLevel(log.ERROR)

	if schema.ProjectLogger == nil {
		schema.ProjectLogger = getLogger()
	}

	// Assures we care loading relative to the application executables directory
	initWorkingDirectory()
}

// Set the working directory to match where the executable is being called from
func initWorkingDirectory() {
	getLogger().Enter()
	// Only correct the WD base path once
	if utils.Flags.WorkingDir == "" {
		// Need to change the working directory to the application root instead of
		// the "cmd" directory where this "_test" file runs so that all test files
		// as well as "config.json" and its referenced JSON schema files load properly.
		wd, _ := os.Getwd()
		// TODO: have package subdir. name passed in and verify the WD
		// indeed "endsWith" that path before removing it. Emit warning if already stripped
		last := strings.LastIndex(wd, "/")
		os.Chdir(wd[:last])

		// Need workingDir to prepend to relative test files
		utils.Flags.WorkingDir, _ = os.Getwd()
		getLogger().Tracef("Set `utils.Flags.WorkingDir`: `%s`\n", utils.Flags.WorkingDir)
	}
	getLogger().Exit()
}
