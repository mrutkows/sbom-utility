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

	"github.com/mrutkows/sbom-utility/schema"
	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
	"github.com/xeipuuv/gojsonschema"
)

const (
	VALID   = true
	INVALID = false
)

func NewCommandValidate() *cobra.Command {
	// NOTE: `RunE` function takes precedent over `Run` (anonymous) function if both provided
	var command = new(cobra.Command)
	command.Use = "validate -i <input-sbom.json>"
	command.Short = "validate input file against its declared SBOM schema."
	command.Long = "validate input file against its declared SBOM schema, if detectable and supported."
	command.RunE = validateCmdImpl
	initCommandValidate(command)
	return command
}

// Add local flags to validate command
func initCommandValidate(command *cobra.Command) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Force a schema file to use for validation (override inferred schema)
	command.Flags().StringVarP(&utils.Flags.ForcedJsonSchemaFile, "force", "", "", "Explicit JSON schema file URL to force for validation; overrides inferred schema")
	// Optional schema "variant" of inferred schema (e.g, "Strict")
	command.Flags().StringVarP(&utils.Flags.Variant, "variant", "", "", "Select named schema variant (e.g., \"strict\"")
	command.Flags().BoolVarP(&utils.Flags.ValidateProperties, "properties", "", true, "Validate customer properties and values.")
}

func validateCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()

	isValid, err := Validate()

	if err != nil {
		getLogger().Error(err)
		os.Exit(ERROR_APPLICATION)
	}

	// ALWAYS output valid/invalid result (as informational)
	message := fmt.Sprintf("document `%s`: valid=[%t]", utils.Flags.InputFile, isValid)
	getLogger().Info(message)

	// Report validation as an error and exit with non-zero return code
	if !isValid {
		getLogger().Error(message)
		os.Exit(ERROR_VALIDATION)
	}

	// Note: this implies os.Exit(0) as the default from main.go (i.e., bash rc=0)
	return nil
}

func Validate() (valid bool, err error) {
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

func ListErrors(errs []gojsonschema.ResultError) {
	lenErrs := len(errs)
	if lenErrs > 0 {
		getLogger().Error(fmt.Sprintf("(%d) Schema errors detected:", lenErrs))
		for i, resultError := range errs {
			getLogger().Error(fmt.Sprintf(">> %d. [%s] [%s]: \"%s\"",
				i+1,
				resultError.Type(),
				resultError.Field(),
				resultError.Description()))
		}
	}
}
