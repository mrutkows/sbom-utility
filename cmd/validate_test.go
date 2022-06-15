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
	"testing"

	"github.com/mrutkows/sbom-utility/utils"
)

// Consolidate test file name declarations

const (
	SCHEMA_VARIANT_NONE = ""
	SCHEMA_VARIANT_IBM  = "ibm"
)

const (

	// CycloneDX
	TEST_CDX_1_3_MIN_REQUIRED     = "test/cyclonedx/cdx-1-3-min-required.json"
	TEST_CDX_1_4_MIN_REQUIRED     = "test/cyclonedx/cdx-1-4-min-required.json"
	TEST_CDX_1_3_IBM_MIN_REQUIRED = "test/cyclonedx/cdx-1-3-ibm-min-required.json"
	TEST_CDX_1_4_IBM_MIN_REQUIRED = "test/cyclonedx/cdx-1-4-ibm-min-required.json"

	// CycloneDX - Data tests
	TEST_CDX_1_3_MANUAL_DATA  = "test/cyclonedx/cdx-1-3-ibm-manual-data-example.json"
	TEST_CDX_1_3_LICENSE_DATA = "test/cyclonedx/cdx-1-3-ibm-min-license-test.json"

	// CycloneDX - Syntax error tests
	TEST_CDX_1_3_SYNTAX_ERR_1 = "test/cyclonedx/cdx-1-3-syntax-err-1.json"
	TEST_CDX_1_3_SYNTAX_ERR_2 = "test/cyclonedx/cdx-1-3-syntax-err-2.json"

	// CycloneDX - Examples
	TEST_CDX_1_2_NPM_JUICE_SHOP = "examples/cyclonedx/juice-shop/bom.json"

	// CycloneDX - IBM Tool samples
	TEST_CDX_1_3_PACKAGE_NPM_ASYNC_CRA = "test/cyclonedx/package/npm/async/cra-discovery.json"
	TEST_CDX_1_3_PACKAGE_NPM_ASYNC_NST = "test/cyclonedx/package/npm/async/nst-sbom.json"

	// SPDX
	TEST_SPDX_2_2_MIN_REQUIRED = "test/spdx/spdx-min-required.json"

	// SPDX - Examples
	TEST_SPDX_2_2_EXAMPLE_1     = "examples/spdx/example1/example1.json"
	TEST_SPDX_2_2_EXAMPLE_2_BIN = "examples/spdx/example2/example2-bin.json"
	TEST_SPDX_2_2_EXAMPLE_2_SRC = "examples/spdx/example2/example2-src.json"
	TEST_SPDX_2_2_EXAMPLE_5_BIN = "examples/spdx/example5/example5-bin.json"
	TEST_SPDX_2_2_EXAMPLE_5_SRC = "examples/spdx/example5/example5-src.json"
	TEST_SPDX_2_2_EXAMPLE_6_LIB = "examples/spdx/example6/example6-lib.json"
	TEST_SPDX_2_2_EXAMPLE_6_SRC = "examples/spdx/example6/example6-src.json"

	// SPDX - IBM Tool samples
	TEST_SPDX_2_2_PACKAGE_NPM_ASYNC_WS = "test/cyclonedx/package/npm/async/whitesource.json"
)

func init() {
	initTestInfra()
	// NOTE: we call this after since the logger would not be properly configured
	// until initTestInfra() is called...
	getLogger().Enter()
	defer getLogger().Exit()
}

// TODO: support "--force" of schema file
func innerValidate(t *testing.T, filename string, variant string) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Copy the test filename to the command line flags where the code looks for it
	utils.Flags.InputFile = filename
	// Set the schema variant where the command line flag would
	utils.Flags.Variant = variant

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

func innerValidateErrorExpected(t *testing.T, filename string, variant string) (bool, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Copy the test filename to the command line flags where the code looks for it
	utils.Flags.InputFile = filename
	// Set the schema variant where the command line flag would
	utils.Flags.Variant = variant

	// Invoke the actual validate function
	isValid, err := Validate()

	// Json SHOULD NOT validate
	if isValid {
		t.Errorf(`%s: SHOULD be invalid, but returned valid (%t) %v `, filename, isValid, err)
	}

	// Validate function SHOULD return the expected error
	if err == nil {
		t.Errorf(`%s: SHOULD return an error, but did not (%t) %v `, filename, isValid, err)
	}

	// Invoke the actual validate function
	return isValid, err
}

// CycloneDX Tests
func TestCdx13MinRequiredBasic(t *testing.T) {
	innerValidate(t, TEST_CDX_1_3_MIN_REQUIRED, SCHEMA_VARIANT_NONE)
}

func TestCdx13IbmMinRequiredBasic(t *testing.T) {
	innerValidate(t, TEST_CDX_1_3_IBM_MIN_REQUIRED, SCHEMA_VARIANT_IBM)
}

func TestCdx14MinRequiredBasic(t *testing.T) {
	innerValidate(t, TEST_CDX_1_4_MIN_REQUIRED, SCHEMA_VARIANT_NONE)
}

func TestCdx14IbmMinRequiredBasic(t *testing.T) {
	innerValidate(t, TEST_CDX_1_4_IBM_MIN_REQUIRED, SCHEMA_VARIANT_IBM)
}

// CycloneDX - Syntax error tests
func TestCdx13SyntaxError1(t *testing.T) {

	filename := TEST_CDX_1_3_SYNTAX_ERR_1
	isValid, err := innerValidateErrorExpected(t, filename, SCHEMA_VARIANT_NONE)

	// Json SHOULD NOT validate
	if isValid {
		t.Errorf(`%s: SHOULD be invalid, but returned valid (%t) %v `, filename, isValid, err)
	}

	// Validate function SHOULD return the expected error
	if err == nil {
		t.Errorf(`%s: SHOULD return an error, but did not (%t) %v `, filename, isValid, err)
	}
}

// CycloneDX - Data tests
func TestCdx13ManualData(t *testing.T) {
	innerValidate(t, TEST_CDX_1_3_MANUAL_DATA, SCHEMA_VARIANT_NONE)
}

func TestCdx13IbmLicenseData(t *testing.T) {
	// NOTE: We only want to test license data variants
	// which does not require a test file with IBM required schema data
	innerValidate(t, TEST_CDX_1_3_LICENSE_DATA, SCHEMA_VARIANT_NONE)
}

// CycloneDX - Examples
func TestCdx12ExampleJuiceShop(t *testing.T) {
	innerValidate(t, TEST_CDX_1_2_NPM_JUICE_SHOP, SCHEMA_VARIANT_NONE)
}

// SPDX Tests
// TODO: Need an SPDX 2.x ibm variant
func TestSpdx22MinRequiredBasic(t *testing.T) {
	innerValidate(t, TEST_SPDX_2_2_MIN_REQUIRED, SCHEMA_VARIANT_NONE)
}

// SPDX - Examples
// TODO: Need an SPDX 2.x "ibm" variant
func TestSpdx22Example1(t *testing.T) {
	innerValidate(t, TEST_SPDX_2_2_EXAMPLE_2_BIN, SCHEMA_VARIANT_NONE)
}

func TestSPDX22Example2Bin(t *testing.T) {
	innerValidate(t, TEST_SPDX_2_2_EXAMPLE_2_BIN, SCHEMA_VARIANT_NONE)
}

func TestSPDX22Example2Src(t *testing.T) {
	innerValidate(t, TEST_SPDX_2_2_EXAMPLE_2_SRC, SCHEMA_VARIANT_NONE)
}

func TestSPDX22Example5Bin(t *testing.T) {
	innerValidate(t, TEST_SPDX_2_2_EXAMPLE_5_BIN, SCHEMA_VARIANT_NONE)
}

func TestSPDX22Example5Src(t *testing.T) {
	innerValidate(t, TEST_SPDX_2_2_EXAMPLE_5_SRC, SCHEMA_VARIANT_NONE)
}

func TestSPDX22Example6Lib(t *testing.T) {
	innerValidate(t, TEST_SPDX_2_2_EXAMPLE_6_LIB, SCHEMA_VARIANT_NONE)
}

func TestSPDX22Example6Src(t *testing.T) {
	innerValidate(t, TEST_SPDX_2_2_EXAMPLE_6_SRC, SCHEMA_VARIANT_NONE)
}

// CycloneDX & SPDX - IBM Tool samples

// Package: NPM: Async
// -------------------

// func TestCdx13PackageNpmAsyncCra(t *testing.T) {
// 	innerValidate(t, TEST_CDX_1_3_PACKAGE_NPM_ASYNC_CRA, SCHEMA_VARIANT_IBM)
// }

// func TestCdx13PackageNpmAsyncNst(t *testing.T) {
// 	innerValidate(t, TEST_CDX_1_3_PACKAGE_NPM_ASYNC_NST, SCHEMA_VARIANT_IBM)
// }

// func TestSpdx22PackageNpmAsyncWs(t *testing.T) {
// 	innerValidate(t, TEST_SPDX_2_2_PACKAGE_NPM_ASYNC_WS, SCHEMA_VARIANT_IBM)
// }
