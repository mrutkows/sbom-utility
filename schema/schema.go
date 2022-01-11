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
var KnownSchemas SchemaConfig

// Representation of SBOM schema instance
type SchemaInstance struct {
	// key string //key: SchemaKey{ID_CYCLONEDX, VERSION_CYCLONEDX_1_3, false},
	Version string `json:"version"`
	File    string `json:"file"`
	Url     string `json:"url"`
	Strict  bool   `json:"strict"`
}

// Representation of SBOM format
type SchemaFormat struct {
	CanonicalName       string           `json:"canonicalName"`
	PropertyKeyFormat   string           `json:"propertyKeyFormat"`
	PropertyKeyVersion  string           `json:"propertyKeyVersion"`
	PropertyValueFormat string           `json:"propertyValueFormat"`
	Schemas             []SchemaInstance `json:"schemas"`
}

// Config
type SchemaConfig struct {
	Formats []SchemaFormat `json:"formats"`
}

type Sbom struct {
	filename    string
	absFilename string
	rawBytes    []byte
	jsonMap     map[string]interface{}
	formatInfo  SchemaFormat
	schemaInfo  SchemaInstance
}

func NewSbom(inputfile string) *Sbom {
	temp := Sbom{
		filename: inputfile,
	}
	// Allocate a map for unmarshalling the raw JSON data
	//temp.jsonMap = make(map[string]interface{})
	return &temp
}

func (sbom *Sbom) GetKeyValueAsString(key string) (string, error) {
	ProjectLogger.Enter()
	if (sbom.jsonMap) == nil {
		err := fmt.Errorf("document object does not have a Map allocated")
		ProjectLogger.Error(err)
		return "", err
	}
	value := sbom.jsonMap[key]

	if value == nil {
		ProjectLogger.Warning(fmt.Sprintf("key: `%s` not found in document map", key))
		return "", nil
	}

	ProjectLogger.Exit(value)
	return value.(string), nil
}

func (sbom *Sbom) UnmarshalSBOM() error {
	ProjectLogger.Enter()

	// validate filename
	if len(sbom.filename) == 0 {
		return fmt.Errorf("schema: invalid SBOM filename: `%s`", sbom.filename)
	}

	// Conditionally append working directory if no abs. path detected
	if len(sbom.filename) > 0 && sbom.filename[0] != '/' {
		sbom.absFilename = utils.Flags.WorkingDir + "/" + sbom.filename
	} else {
		sbom.absFilename = sbom.filename
	}

	// Open our jsonFile
	jsonFile, err := os.Open(sbom.absFilename)

	// if input file cannot be opened, log it and terminate
	if err != nil {
		ProjectLogger.Error(err)
		os.Exit(-1)
	}

	ProjectLogger.Info(fmt.Sprintf("Successfully Opened: `%s`", sbom.filename))

	// defer the closing of our jsonFile
	defer jsonFile.Close()

	// read our opened jsonFile as a byte array.
	// TODO: check for error
	sbom.rawBytes, _ = ioutil.ReadAll(jsonFile)
	ProjectLogger.Trace(fmt.Sprintf("&rawBytes=[%p]", &(sbom.rawBytes)))
	ProjectLogger.Trace(fmt.Sprintf("rawBytes[:100]=[%s]", sbom.rawBytes[:100]))

	// Attempt to unmarshal the prospective JSON document to a map
	sbom.jsonMap = make(map[string]interface{})
	errUnmarshal := json.Unmarshal(sbom.rawBytes, &(sbom.jsonMap))
	if errUnmarshal != nil {
		ProjectLogger.Error(errUnmarshal)
	}

	// Search the document keys/values for known SBOM formats and schema
	sbom.FindFormatAndSchema()

	// Print the data type of result variable
	ProjectLogger.Info(fmt.Sprintf("sbom.jsonMap(%s)", reflect.TypeOf(sbom.jsonMap)))
	ProjectLogger.Exit()
	return nil
}

func (sbom *Sbom) FindFormatAndSchema() error {
	ProjectLogger.Enter()

	// Iterate over known formats to see if SBOM document contains a known value
	for _, format := range KnownSchemas.Formats {

		// See if the format identifier key exists and is a known value
		fmt.Printf("format=%v", format)
		formatValue, _ := sbom.GetKeyValueAsString(format.PropertyKeyFormat)
		fmt.Printf("formatValue=%s, PropertyValueFormat=%s", formatValue, format.PropertyValueFormat)
		if formatValue == format.PropertyValueFormat {
			versionValue, _ := sbom.GetKeyValueAsString(format.PropertyKeyVersion)
			// TODO: IFF exists then search to see if this schema version is known
			// Copy format info into Sbom context
			sbom.formatInfo = format
			sbom.findSchema(format, versionValue)
			return nil
		}
	}

	ProjectLogger.Exit()
	return nil
}

func (sbom *Sbom) findSchema(format SchemaFormat, version string) error {
	ProjectLogger.Enter()

	// Iterate over known schema versions to see if SBOM's version is supported
	for _, schema := range format.Schemas {
		fmt.Printf("schema=%v", schema)
		// Compare requested version to current schema version
		curSchemaVersion, _ := sbom.GetKeyValueAsString(format.PropertyKeyVersion)
		//fmt.Printf("version=%s, PropertyValueVersion=%s", version, curSchemaVersion)
		if version == curSchemaVersion {
			ProjectLogger.Info(fmt.Sprintf("Schema version `%s` supported.", version))
			// Copy schema info into Sbom context
			sbom.schemaInfo = schema
			return nil
		}
	}
	ProjectLogger.Error(fmt.Sprintf("Schema version `%s` NOT supported.", version))
	ProjectLogger.Exit()
	return nil
}

// TODO: use a Hash map to look up known schemas using the following `SchemaKey`

// Unique Identifier for an SBOM schema
// The prospective JSON document MUST include (at least) 2 identifying property names
// to be a prospective match for a known SBOM schema
// If both property names are found, then their respective values can be used
// to construct a key (i.e., the SchemaKey) into our hashmap of declared schemas
// type SchemaKey struct {
// 	formatId      string
// 	schemaVersion string
// 	strict        bool
// }

// TODO: look into creating a schema interface
// func NewSchemaKey(id string, version string, strict bool) *SchemaKey {
// 	// TODO: is it possible (or necessary) to validate id, version args.
// 	return &SchemaKey{
// 		formatId:      id,
// 		schemaVersion: version,
// 		strict:        strict,
// 	}
// }

// Struct keys, on average, provide best performance taking into
// account flexibility (based upon several documented benchmarks).
// Only concatenated keys (of same literal type) might perform better,
// but are much less idiomatic and prone to key construction errors.
// For example:
// var knownSchemas = map[SchemaKey]SchemaInstance{
// 	{ID_SPDX, VERSION_SPDX_2_2, false}: {
// 		version: VERSION_SPDX_2_2,
// 		file:    SCHEMA_SPDX_2_2_2_LOCAL,
// 		url:     SCHEMA_SPDX_2_2_2_REMOTE,
// 	},
// 	{ID_CYCLONEDX, VERSION_CYCLONEDX_1_3, false}: {
// 		version: VERSION_CYCLONEDX_1_3,
// 		file:    SCHEMA_CYCLONEDX_1_3_LOCAL,
// 		url:     SCHEMA_CYCLONEDX_1_3_REMOTE,
// 	},
// }
