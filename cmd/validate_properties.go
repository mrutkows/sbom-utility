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

	"github.com/mrutkows/sbom-utility/schema"
	"github.com/mrutkows/sbom-utility/utils"
	"github.com/xeipuuv/gojsonschema"
)

// This function is used to validate required or optional prescriptive properties
// and if present, their values also adhere to specified requirements
func ValidateProperties() (valid bool, err error) {
	getLogger().Enter()
	defer getLogger().Exit(valid, err)

	// Attempt to load and unmarshal the input file as a Json document
	document, errLoad := LoadInputFileAndUnmarshal()

	if errLoad != nil {
		getLogger().Error(errLoad)
		return INVALID, errLoad
	}

	// Find the schema to use for validation (either "forced" via cmd line or inferred from document)
	if utils.Flags.ForcedJsonSchemaFile != "" {
		document.SchemaInfo = *new(schema.SchemaInstance)
		document.SchemaInfo.File = utils.Flags.ForcedJsonSchemaFile
		getLogger().Info(fmt.Sprintf("Validating document using forced schema (i.e., `--force %s`)", utils.Flags.ForcedJsonSchemaFile))
	} else {
		// Search the document keys/values for known SBOM formats and schema
		errFind := document.FindFormatAndSchema()

		// Load schema based upon document declarations of schema format and version
		if errFind != nil {
			getLogger().Error(errFind)
			return INVALID, errFind
		}
	}

	// TODO: support remote schema load (via URL) with a flag (default should always be local file for security)
	// TODO: support "latest" schema load (flag) for version (i.e., override version declared in document)
	var schemaURL = document.SchemaInfo.File
	getLogger().Info(fmt.Sprintf("Loading schema `%s`...", schemaURL))
	schemaLoader := gojsonschema.NewReferenceLoader(schemaURL)

	// create a reusable schema object (to validate multiple documents)
	schema, err := gojsonschema.NewSchema(schemaLoader)

	if err != nil {
		getLogger().Error(err)
		return INVALID, err
	}

	getLogger().Info(fmt.Sprintf("Schema `%s` loaded.", schemaURL))

	// Create a JSON load for the actual document
	documentLoader := gojsonschema.NewReferenceLoader("file://" + utils.Flags.InputFile)

	result, errValidate := schema.Validate(documentLoader)
	getLogger().Trace(fmt.Sprintf("result.Valid(): `%t`.", result.Valid()))

	// Catch general errors from the validation module itself
	// Note: actual validation errors are in the `result` object
	if errValidate != nil {
		getLogger().Error(errValidate)
		return INVALID, errValidate
	}

	// Log each validation result errors (i.e., actual validation errors found in the document)
	errs := result.Errors()
	ListErrors(errs)

	return result.Valid(), nil
}
