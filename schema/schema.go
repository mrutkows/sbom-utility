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
	"errors"
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
	Latest  bool   `json:"latest"`
	Variant string `json:"variant"`
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

// Candidate SBOM document (context) information
type Sbom struct {
	filename    string
	absFilename string
	rawBytes    []byte
	JsonMap     map[string]interface{}
	FormatInfo  SchemaFormat
	SchemaInfo  SchemaInstance
}

func NewSbom(inputfile string) *Sbom {
	temp := Sbom{
		filename: inputfile,
	}
	// NOTE: the Map is allocated (i.e., using `make`) as part of `UnmarshalSBOM` method
	return &temp
}

func (sbom *Sbom) GetFilename() string {
	return sbom.filename
}

func (sbom *Sbom) GetMap() map[string]interface{} {
	return sbom.JsonMap
}

func (sbom *Sbom) GetKeyValueAsString(key string) (string, error) {
	ProjectLogger.Enter(key)
	if (sbom.JsonMap) == nil {
		err := fmt.Errorf("document object does not have a Map allocated")
		ProjectLogger.Error(err)
		ProjectLogger.Exit(err)
		return "", err
	}
	value := sbom.JsonMap[key]

	if value == nil {
		ProjectLogger.Trace(fmt.Sprintf("key: `%s` not found in document map", key))
		ProjectLogger.Exit(nil)
		return "", nil
	}

	ProjectLogger.Exit(key, ':', value)
	return value.(string), nil
}

func (sbom *Sbom) UnmarshalSBOM() error {
	ProjectLogger.Enter()
	defer ProjectLogger.Exit()

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
	var errReadAll error
	sbom.rawBytes, errReadAll = ioutil.ReadAll(jsonFile)
	if errReadAll != nil {
		ProjectLogger.Error(errReadAll)
	}
	ProjectLogger.Trace(fmt.Sprintf("\n  >> rawBytes[:100]=[%s]", sbom.rawBytes[:100]))

	// Attempt to unmarshal the prospective JSON document to a map
	sbom.JsonMap = make(map[string]interface{})
	errUnmarshal := json.Unmarshal(sbom.rawBytes, &(sbom.JsonMap))
	if errUnmarshal != nil {

		DisplayUnmarshalErrorDetails(sbom.rawBytes, errUnmarshal)

		// TODO: make an "ExitError() method in log package"
		ProjectLogger.Error(errUnmarshal)
		return errUnmarshal
	}

	// Print the data type of result variable
	ProjectLogger.Trace(fmt.Sprintf("sbom.jsonMap(%s)", reflect.TypeOf(sbom.JsonMap)))
	return nil
}

func (sbom *Sbom) FindFormatAndSchema() error {
	ProjectLogger.Enter()
	defer ProjectLogger.Exit()

	// Iterate over known formats to see if SBOM document contains a known value
	for _, format := range KnownSchemas.Formats {

		// See if the format identifier key exists and is a known value
		formatValue, _ := sbom.GetKeyValueAsString(format.PropertyKeyFormat)

		if formatValue == format.PropertyValueFormat {
			versionValue, _ := sbom.GetKeyValueAsString(format.PropertyKeyVersion)

			// Copy format info into Sbom context
			sbom.FormatInfo = format
			errFindSchema := sbom.findSchema(format, versionValue)

			if errFindSchema != nil {
				ProjectLogger.Error(errFindSchema.Error())
				return errFindSchema
			}
			return nil
		}
	}

	// Did not find the format in our list
	errFindFormat := errors.New("schema: unknown format")
	ProjectLogger.Error(errFindFormat.Error())
	return errFindFormat
}

func (sbom *Sbom) findSchema(format SchemaFormat, version string) error {
	ProjectLogger.Enter()
	defer ProjectLogger.Exit()

	// Iterate over known schema versions to see if SBOM's version is supported
	for _, schema := range format.Schemas {

		// Compare requested version to current schema version
		//curSchemaVersion, _ := sbom.GetKeyValueAsString(format.PropertyKeyVersion)
		ProjectLogger.Trace(fmt.Sprintf("Comparing sbom.Version: `%s` to schema.version: `%s` ...", version, schema.Version))
		if version == schema.Version {
			// Copy schema info into Sbom context
			if utils.Flags.Variant == schema.Variant {
				ProjectLogger.Trace(fmt.Sprintf("Schema.Variant: matched: `%s`", schema.Variant))
				sbom.SchemaInfo = schema
				return nil
			} else {
				ProjectLogger.Trace(fmt.Sprintf("Schema.Variant: `%s` did not match requested Variant: `%s`", schema.Variant, utils.Flags.Variant))
			}
		}
	}

	errSchema := fmt.Errorf("schema: unsupported version `%s` for format `%s`", version, format.CanonicalName)
	ProjectLogger.Error(errSchema.Error())
	return errSchema
}

func DisplayUnmarshalErrorDetails(data []byte, err error) {

	if jsonError, ok := err.(*json.SyntaxError); ok {
		line, character := calcLineAndCharacterPos(data, jsonError.Offset)
		ProjectLogger.Error(fmt.Sprintf("JSON Syntax error: offset: %d, line %d, character %d: %v\n", jsonError.Offset, line, character, jsonError.Error()))

	} else if jsonError, ok := err.(*json.UnmarshalTypeError); ok {
		line, character := calcLineAndCharacterPos(data, jsonError.Offset)
		ProjectLogger.Error(fmt.Sprintf("JSON Unmarshal error: offset: %d, line %d, character %d: %v\n", jsonError.Offset, line, character, jsonError.Error()))
	}
}

const LF byte = 0x0a

func calcLineAndCharacterPos(data []byte, offset int64) (linenum int, charnum int) {

	line := 1
	char := 0
	intOffset := int(offset)

	for i := 0; i < len(data) && i < intOffset; i, char = i+1, char+1 {

		if data[i] == LF {
			linenum++
			//fmt.Printf("NEWLINE (%v): total: %d, offset: %d\n", LF, line, char)
			char = 0
		}
	}

	return line, char
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
