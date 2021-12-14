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

package schema

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"

	"github.com/mrutkows/sbom-utility/log"
	"github.com/mrutkows/sbom-utility/utils"
)

var ProjectLogger *log.MiniLogger

// Standard
type Standard uint

const (
	STANDARD_UNKNOWN = iota
	STANDARD_SPDX
	STANDARD_CYCLONEDX
)

// Supported schemas will be identified (or "keyed") uniquely using values:
// - Format ID (e.g., "SPDXRef-DOCUMENT", "CycloneDX") - identifies the format/standard
// - Schema version (e.g., "SPDX-2.2", "" )
// ASSUMPTIONS:
// - Since we see that both SPDX and CycloneDX both support "semver" of their specification versions
// BUT, they only provide the "MAJOR.MINOR" components of "semver" we will use the
// "latest" ".PATCH" version of the JSON schema to test against
// NOTE: If any of these 3 components are not found in an SBOM then the schema is
// not deterministic.
// TODO:  support "override" or "supplemental" (defaults) to be provided on
// the command line.
// TODO: Allow for discrete "semver" for a scheam to be provided as an override
// that includes full "MAJOR.MINOR.PATCH" granularity

// Format ID (key component)
const (
	ID_SPDX      = "SPDXRef-DOCUMENT"
	ID_CYCLONEDX = "CycloneDX"
)

// Version (key component)
const (
	VERSION_SPDX_2_2      = "SPDX-2.2"
	VERSION_CYCLONEDX_1_2 = "1.2"
	VERSION_CYCLONEDX_1_3 = "1.3"
)

// Document property keys
// JSON document property keys to lookup values in their respective SBOM formats
const (
	// SPDX
	PROPKEY_ID_SPDX      = "SPDXID"
	PROPKEY_VERSION_SPDX = "spdxVersion"
	// CycloneDX
	PROPKEY_ID_CYCLONEDX      = "bomFormat"
	PROPKEY_VERSION_CYCLONEDX = "specVersion"
)

// TODO: Support remote schema retrieval as an optional program flag
// However, we want to default to local for performance where possible
// as well as plan for local, secure bundling of schema with this utility
// in CI build systems (towards improved security, isolated builds)
// NOTE: we have also found that standards orgs. freely move their schema files
// within SCM systems thereby being a cause for remote retrieval failures.
const (
	SCHEMA_SPDX_2_2_2_LOCAL            = "file://schema/spdx/2.2/spdx-schema.json"
	SCHEMA_SPDX_2_2_2_REMOTE           = "https://github.com/spdx/spdx-spec/blob/master/schemas/spdx-schema.json"
	SCHEMA_CYCLONEDX_1_3_LOCAL         = "file://schema/cyclonedx/1.3/bom-1.3.schema.json"
	SCHEMA_CYCLONEDX_1_3_REMOTE        = "https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3.schema.json"
	SCHEMA_CYCLONEDX_1_3_STRICT_LOCAL  = "file://schema/cyclonedx/1.3/bom-1.3-strict.schema.json"
	SCHEMA_CYCLONEDX_1_3_STRICT_REMOTE = "https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3-strict.schema.json"
)

// The prospective JSON document MUST include (at least) these 2 property names
// to be a prospective match for a known SBOM schema
// If both property names are found, then their respective values can be used
// to construct a key (i.e., the SchemaKey) into our hashmap of declared schemas
type SchemaKeyPropertyNames struct {
	propFormat  string
	propVersion string
}

// Unique Identifier for an SBOM schema
type SchemaKey struct {
	formatId      string
	schemaVersion string
	strict        bool
}

// Internal representation of SBOM schema
type Schema struct {
	key       SchemaKey // Key values may be useful to downstream processors
	standard  Standard
	schemaURL string
}

// Struct keys, on average, provide best performance taking into
// account flexibility (based upon several documented benchmarks).
// Only concatenated keys (of same literal type) might perform better,
// but are much less idiomatic and prone to key construction errors.
var KnownSchemas = map[SchemaKey]Schema{
	{ID_SPDX, VERSION_SPDX_2_2, false}: {
		key:       SchemaKey{ID_SPDX, VERSION_SPDX_2_2, false},
		standard:  STANDARD_SPDX,
		schemaURL: SCHEMA_SPDX_2_2_2_LOCAL,
	},
	{ID_CYCLONEDX, VERSION_CYCLONEDX_1_3, false}: {
		key:       SchemaKey{ID_CYCLONEDX, VERSION_CYCLONEDX_1_3, false},
		standard:  STANDARD_CYCLONEDX,
		schemaURL: SCHEMA_CYCLONEDX_1_3_LOCAL,
	},
}

type Sbom struct {
	filename    string
	absFilename string
	rawBytes    []byte
	jsonMap     map[string]interface{}
	standard    Standard
	schemaId    string
}

func NewSbom() *Sbom {
	temp := Sbom{
		filename: "",
		standard: STANDARD_UNKNOWN,
		schemaId: "",
	}
	temp.jsonMap = make(map[string]interface{})
	return &temp
}

func (sbom *Sbom) UnmarshalSBOM(filename string) error {

	// Open our jsonFile
	sbom.filename = filename

	// Conditionally append working directory if no abs. path detected
	if len(filename) > 0 && filename[0] != '/' {
		sbom.absFilename = utils.Flags.WorkingDir + "/" + filename
	}
	jsonFile, err := os.Open(sbom.absFilename)

	// if we os.Open returns an error then handle it
	if err != nil {
		ProjectLogger.Error(err)
		os.Exit(-1)
	}

	ProjectLogger.Info(fmt.Sprintf("Successfully Opened: `%s`", sbom.filename))

	// defer the closing of our jsonFile
	defer jsonFile.Close()

	// read our opened jsonFile as a byte array.
	//	rawBytes, _ := ioutil.ReadAll(jsonFile)
	//	fmt.Printf("rawBytes=[%p]\n", &rawBytes)
	//	sbom.rawBytes = rawBytes
	//sbom.rawBytes
	sbom.rawBytes, _ = ioutil.ReadAll(jsonFile)
	fmt.Printf("rawBytes=[%p]\n", &(sbom.rawBytes))

	// Declared an empty map interface
	//var result map[string]interface{}

	// Attempt to unmarshal the prospective JSON document to a map
	sbom.jsonMap = make(map[string]interface{})
	errUnmarshal := json.Unmarshal(sbom.rawBytes, &(sbom.jsonMap))
	if errUnmarshal != nil {
		ProjectLogger.Error(errUnmarshal)
	}

	// Detect required identifying schema elements and values
	// for SPDX and CycloneDX schemas
	spdxVersion := sbom.jsonMap["spdxVersion"].(string)
	ProjectLogger.Trace(fmt.Sprintf("spdxVersion=`%s`", spdxVersion))

	// Print the data type of result variable
	ProjectLogger.Trace(fmt.Sprintf("%s\n", reflect.TypeOf(sbom.jsonMap)))

	return nil
}
