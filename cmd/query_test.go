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
	"strings"
	"testing"

	"github.com/mrutkows/sbom-utility/log"
	"github.com/mrutkows/sbom-utility/utils"
)

// NOTE: Go test framework uses the "flags" package and all we need
// do is declare a new global for it to be recognized.
// USAGE: to set on command line and have it parsed, simply append
// it as follows: '--args -trace'
var TestLogLevelTrace = flag.Bool("trace", false, "")
var TestLogLevelError = flag.Bool("error", false, "")

// TODO: Consolidate query declarations

func init() {
	initTestInfra()
	getLogger().Enter()
	getLogger().Exit()
}

func innerQuery(t *testing.T, filename string, queryRequest *QueryRequest, autofail bool) error {
	getLogger().Enter()

	// in order for us to utilize command line flags with "go test", we
	// must individually declare and access them via the "flags" package
	if *TestLogLevelTrace {
		// trace explicitely requested, set log level and turn off quite mode
		getLogger().SetLevel(log.TRACE)
		getLogger().SetQuietMode(false)
	} else if *TestLogLevelError {
		getLogger().SetLevel(log.ERROR)
		getLogger().SetQuietMode(false)
	}

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
	var response = new(QueryResult)

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
	getLogger().Exit()
	return nil
}

func printResult(iResult interface{}) {
	// TODO: we default to "json" output format, but should be able to supply via flag
	// we would need solid use cases to support other formats...
	fResult, _ := utils.ConvertMapToJson("", iResult)
	// Output the JSON data directly to stdout (not subject to log-level)
	fmt.Printf("%s\n", fResult)
}

// ===========================================
// PASS tests
// ===========================================

// CDX 1.3, IBM Min. Required
func TestQueryCdx13IbmMinMetadataTimestampString(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.timestamp",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataTimestampField(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "timestamp",
		fromObjectsRaw:  "metadata",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentName(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "name",
		fromObjectsRaw:  "metadata.component.name",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataSupplier(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.supplier",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataManufacturer(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.manufacture",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentLicenses(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.component.licenses",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentLicensesLicenseExpression(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "license,expression",
		fromObjectsRaw:  "metadata.component.licenses",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataComponent(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.component",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentSupplier(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.component.supplier",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentPublisher(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.component.publisher",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentHashes(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.component.hashes",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataComponentProperties(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.component.properties",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

func TestQueryCdx13IbmMinMetadataNameVersion(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "*",
		fromObjectsRaw:  "metadata.component.foo",
	}
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, true)
}

// CDX 1.3, NPM Async
func TestQueryCdx13NpmAsyncMetadataComponentNameVersion(t *testing.T) {
	request := QueryRequest{
		selectFieldsRaw: "name,version",
		fromObjectsRaw:  "metadata.component.name",
	}
	innerQuery(t, "test/cyclonedx/package/npm/async/cra-discovery.json", &request, true)
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
	innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, false)
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
	err := innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, false)

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
	err := innerQuery(t, "test/cyclonedx/cdx-1-3-ibm-min-required.json", &request, false)

	// Assure we received an error with the expected key phrases
	EvaluateErrorAndKeyPhrases(t, err, MSG_QUERY_INVALID_SELECT_CLAUSE, errMessages)
}
