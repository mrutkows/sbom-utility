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

// Consolidate test file name declarations
const (
	// Granular tests
	TEST_CDX_1_3_MIN_REQUIRED         = "test/cyclonedx/cdx-1-3-min-required.json"
	TEST_CDX_1_3_MIN_REQUIRED_VAR_IBM = "test/cyclonedx/cdx-1-3-ibm-min-required.json"

	// Application examples
	TEST_CDX_1_2_NPM_JUICE_SHOP = "examples/cyclonedx/juice-shop/bom.json"
)

// TODO: look into passing args. to test cases
// See: https://stackoverflow.com/questions/47045445/idiomatic-way-to-pass-variables-to-test-cases-in-golang/51102972
//
// var password string
//
// func init() {
//	flag.StringVar(&password, "password", "", "Database Password")
//}
//
// $ go test github.com/user/project -password=123345

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

// TODO: support "--force" of schema file
func innerValidate(t *testing.T, filename string) {

	// Copy the test filename to the command line flags were the code looks for it
	utils.Flags.InputFile = filename

	// Invoke the actual validate function
	isValid, errValidate := Validate()

	// Unexpected error
	if errValidate != nil {
		t.Errorf(`%s: error (%t) %v `, filename, isValid, errValidate)
	}

	// SBOM is valid or not against declared schema
	if !isValid {
		t.Errorf(`%s: invalid (%t) %v `, filename, isValid, errValidate)
	}

}
func TestCDX13MinRequiredBasic(t *testing.T) {
	innerValidate(t, TEST_CDX_1_3_MIN_REQUIRED)
}

func TestCDX13MinRequiredVariantIBM(t *testing.T) {
	innerValidate(t, TEST_CDX_1_3_MIN_REQUIRED_VAR_IBM)
}

func TestCDX12ExampleJuiceShop(t *testing.T) {
	innerValidate(t, TEST_CDX_1_2_NPM_JUICE_SHOP)
}
