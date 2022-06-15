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
)

func init() {
	initTestInfra()
	getLogger().Enter()
	getLogger().Exit()
}

// CycloneDX
const (
	TEST_CDX_1_3_IBM_MIN_LICENSE_TEST_FILE = "test/cyclonedx/cdx-1-3-ibm-min-license-test.json"
)

func TestLicenseSpdxIdSimple(t *testing.T) {
	ID := "MIT"
	if !IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `false`: Expected `true`.", ID)
	}
}

func TestLicenseSpdxIdComplex(t *testing.T) {
	ID := "AGPL-3.0-or-later"
	if !IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `false`: Expected `true`.", ID)
	}
}

func TestLicenseSpdxIdFailEmptyString(t *testing.T) {
	ID := ""
	if IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `true`: Expected `false`.", ID)
	}
}

func TestLicenseSpdxIdFailBadCharacter1(t *testing.T) {
	ID := "?"
	if IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `true`: Expected `false`.", ID)
	}
}

func TestLicenseSpdxIdFailBadCharacter2(t *testing.T) {
	ID := "MIT+Apache-2.0"
	if IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `true`: Expected `false`.", ID)
	}
}

func TestLicenseSpdxIdFailWhiteSpace(t *testing.T) {
	ID := "Apache 2.0"
	if IsValidSpdxId(ID) {
		t.Errorf("IsValidSpdxId(`%s`) == `true`: Expected `false`.", ID)
	}
}

func TestLicenseHash(t *testing.T) {
	//TODO
}

func TestLicenseListJSON(t *testing.T) {
	// TODO Load a test input SBOM with licenses inside
	// utils.Flags.InputFile = TEST_CDX_1_3_IBM_MIN_LICENSE_TEST_FILE

	// document, errLoad := LoadInputFileAndUnmarshal()

	// if errLoad != nil {
	// 	getLogger().Error(errLoad)
	// 	return errLoad
	// }

	// var buffer bytes.Buffer
	// output := bufio.NewWriter(&buffer)
	// DisplayLicensesJson(output)
	// // TODO Actually test it is more specifically an array of CDX LicenseChoice (struct)

	// if !utils.IsValidJSON(buffer.String()) {
	// 	t.Errorf("DisplayLicensesJson(): did not produce valid JSON output")
	// }
}
