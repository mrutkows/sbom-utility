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
	"strings"
	"testing"

	"github.com/mrutkows/sbom-utility/utils"
)

const (
	SBOM_CDX_1_3_JSON_IBM_MIN_REQ       = "test/cyclonedx/cdx-1-3-ibm-min-required.json"
	SBOM_CDX_1_3_JSON_PKG_NPM_ASYNC_CRA = "test/cyclonedx/package/npm/async/cra-discovery.json"
)

// TODO: Consolidate query declarations

func init() {
	initTestInfra()
	getLogger().Enter()
	getLogger().Exit()
}

func innerQuery(t *testing.T, filename string, queryRequest *QueryRequest, autofail bool) error {
	getLogger().Enter()
	defer getLogger().Exit()

	// Parse normalized query clauses
	queryRequest.parseQueryClauses()

	// Copy the test filename to the command line flags were the code looks for it
	utils.Flags.InputFile = filename

	// Note: returns error if either file load or unmarshal to JSON map fails
	document, errLoad := LoadInputFileAndUnmarshal()

	if errLoad != nil {
		getLogger().Error(errLoad)
		t.Errorf("failed to load file: %s", filename)
		return errLoad
	}

	// allocate response/result object
	var response = new(QueryResponse)

	iResult, errQuery := query(document.JsonMap, queryRequest, response)

	// if the query resulted in a failure
	if errQuery != nil {
		// if tests asks us to report a FAIL to the test framework
		if autofail {
			t.Errorf("%s: failed: %v\nquery:\n%s", filename, errQuery, queryRequest)
		}
		return errQuery
	}

	// TODO: call Stringer on result (convert to JSON string) and output here if TRACE
	printResult(iResult)
	return nil
}

func printResult(iResult interface{}) {
	if !*TestLogQuiet {
		// TODO: we default to "json" output format, but should be able to supply via flag
		// we would need solid use cases to support other formats...
		fResult, _ := utils.ConvertMapToJson("", iResult)
		// Output the JSON data directly to stdout (not subject to log-level)
		fmt.Printf("%s\n", fResult)
	}
}

// ===========================================
// PASS tests
// ===========================================

// CDX 1.3, IBM Min. Required
func TestQueryCdx13IbmMinBomFormatSpecVersion(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "bomFormat,specVersion",
		fromObjectsRaw:  "",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

func TestQueryCdx13IbmMinMetadataTimestampField(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "timestamp",
		fromObjectsRaw:  "metadata",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

func TestQueryCdx13IbmMinMetadataComponent(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.component",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentName(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "name",
		fromObjectsRaw:  "metadata.component",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

func TestQueryCdx13IbmMinMetadataNameVersion(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "name,version",
		fromObjectsRaw:  "metadata.component",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

func TestQueryCdx13IbmMinMetadataSupplier(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.supplier",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

func TestQueryCdx13IbmMinMetadataManufacturer(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.manufacture",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentLicenses(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "licenses",
		fromObjectsRaw:  "metadata.component",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentSupplier(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "supplier",
		fromObjectsRaw:  "metadata.component",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentPublisher(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "publisher",
		fromObjectsRaw:  "metadata.component",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

// NOTE: hashes is an []interface
// func TestQueryCdx13IbmMinMetadataComponentHashes(t *testing.T) {
// 	request := QueryRequest{
// 		selectFieldsRaw: "*",
// 		fromObjectsRaw:  "metadata.component.hashes",
// 	}
// 	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
// }

// NOTE: licenses is an []interface
func TestQueryCdx13IbmMinMetadataComponentLicensesLicenseExpression(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "license,expression",
		fromObjectsRaw:  "metadata.component.licenses",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

// NOTE: properties is an []interface
func TestQueryCdx13IbmMinMetadataComponentProperties(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "properties",
		fromObjectsRaw:  "metadata.component",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, true)
}

// CDX 1.3, NPM Async, CRA
func TestQueryCdx13NpmAsyncMetadataComponentNameVersionCRA(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "name,version",
		fromObjectsRaw:  "metadata.component",
	}
	innerQuery(t, SBOM_CDX_1_3_JSON_PKG_NPM_ASYNC_CRA, &request, true)
}

// ===========================================
// FAIL tests
// ===========================================

func EvaluateErrorAndKeyPhrases(t *testing.T, err error, expected string, messages []string) {

	if err == nil {
		t.Errorf("error expected: %s", expected)
	} else {
		getLogger().Tracef("Testing error message for the following substring:\n%v", messages)
		for _, substring := range messages {
			if !strings.Contains(err.Error(), substring) {
				t.Errorf("substring: %s; not found in: %s", substring, err.Error())
			}
		}
	}
}

func TestQueryFailCdx13IbmMinMetadataComponentFoo(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.component.foo",
	}

	// Use innerquery, but turn "autofail" to false as we want to
	// test for the expected error
	err := innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, false)

	if err == nil {
		t.Errorf(err.Error())
	}
}

func TestQueryFailTypeStringCdx13IbmMinMetadataComponentName(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.component.name",
	}
	errMessages := []string{
		MSG_QUERY_INVALID_FROM_CLAUSE,
		MSG_ERROR_FROM_KEY_INVALID_OBJECT,
	}

	// We must handle the error to verify it is the one we expect
	err := innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, false)

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, MSG_QUERY_INVALID_FROM_CLAUSE, errMessages)
}

func TestQueryFailCdx13IbmMinMetadataComponentNameWithWildcard(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "name,*",
		fromObjectsRaw:  "metadata.component",
	}

	errMessages := []string{
		MSG_QUERY_INVALID_SELECT_CLAUSE,
		MSG_ERROR_SELECT_WILDARD,
	}

	// We must handle the error to verify it is the one we expect
	err := innerQuery(t, SBOM_CDX_1_3_JSON_IBM_MIN_REQ, &request, false)

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, MSG_QUERY_INVALID_SELECT_CLAUSE, errMessages)
}
