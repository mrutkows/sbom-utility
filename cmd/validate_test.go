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
	"strings"
	"testing"

	"github.com/mrutkows/sbom-utility/log"
	"github.com/mrutkows/sbom-utility/schema"
	"github.com/mrutkows/sbom-utility/utils"
)

const (
	FORMAT_VALUE_CYCLONEDX = "CycloneDX"
	FORMAT_VALUE_SPDX      = "SPDXRef-DOCUMENT"
)

func init() {

	// The packages we call need to have their loggers created
	ProjectLogger = log.NewLogger(log.ERROR)
	schema.ProjectLogger = ProjectLogger

	// Need to change the working directory to the application root instead of
	// the "cmd" directory where this "_test" file runs so that all test files
	// as well as "config.json" and its referenced JSON schema files load properly.
	wd, _ := os.Getwd()
	last := strings.LastIndex(wd, "/")
	os.Chdir(wd[:last])

	// Need workingDir to prepend to relative test files
	utils.Flags.WorkingDir, _ = os.Getwd()
	fmt.Printf("utils.Flags.WorkingDir: `%s`\n", utils.Flags.WorkingDir)

	// Load application configuration files
	// i.e., Format/Schemas in this case
	errCfg := schema.LoadFormatBasedSchemas(DEFAULT_CONFIG)
	if errCfg != nil {
		ProjectLogger.Error(errCfg.Error())
	}

}
func TestMinRequiredCycloneDX13(t *testing.T) {
	sbomFilename := "test/cyclonedx/cdx-1-3-min-required.json"
	utils.Flags.InputFile = sbomFilename

	isValid, errValidate := Validate()

	if errValidate != nil {
		t.Errorf(`%s: error (%t) %v `, sbomFilename, isValid, errValidate)
	}

	if !isValid {
		t.Errorf(`%s: invalid (%t) %v `, sbomFilename, isValid, errValidate)
	}

}

func TestExampleCycloneDX13JuiceShop(t *testing.T) {
	sbomFilename := "examples/cyclonedx/juice-shop/bom.json"
	utils.Flags.InputFile = sbomFilename

	isValid, errValidate := Validate()

	if errValidate != nil {
		t.Errorf(`%s: error (%t) %v `, sbomFilename, isValid, errValidate)
	}

	if !isValid {
		t.Errorf(`%s: invalid (%t) %v `, sbomFilename, isValid, errValidate)
	}

}
