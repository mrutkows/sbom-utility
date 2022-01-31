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

	"github.com/mrutkows/sbom-utility/log"
	"github.com/mrutkows/sbom-utility/schema"
	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
	"github.com/xeipuuv/gojsonschema"
)

const (
	VALID   = true
	INVALID = false

	ERROR_APPLICATION = 2
	ERROR_VALIDATION  = 1
)

var validateCmd = &cobra.Command{
	Use:   "validate -i <input-sbom.json>",
	Short: "validate input file against its declared SBOM schema.",
	Long:  "validate input file against its declared SBOM schema, if detectable and supported.",
	// NOTE: `RunE` function takes precedent over `Run` (anonymous) function if both provided
	// Run: func(cmd *cobra.Command, args []string) {}
	RunE: validateCmdImpl,
}

func init() {
	ProjectLogger.Enter()
	// Add local flags to validate command
	//validateCmd.Flags().BoolVarP(&utils.Flags.Strict, "strict", "", false, "use `strict` schema when available")
	// Force a schema file to use for validation (override inferred schema)
	validateCmd.Flags().StringVarP(&utils.Flags.ForcedJsonSchemaFile, "force", "", "", "Explicit JSON schema file URL to force for validation; overrides inferred schema")
	// Optional schema "variant" of inferred schema (e.g, "Strict")
	validateCmd.Flags().StringVarP(&utils.Flags.Variant, "variant", "", "", "Select named schema variant (e.g., \"strict\"")
	rootCmd.AddCommand(validateCmd)
	ProjectLogger.Exit()
}

func validateCmdImpl(cmd *cobra.Command, args []string) error {
	ProjectLogger.Enter()
	isValid, err := Validate()

	if err != nil {
		ProjectLogger.Error(err)
		os.Exit(ERROR_APPLICATION)
	}

	message := fmt.Sprintf("document `%s`: valid=[%t]", utils.Flags.InputFile, isValid)
	if isValid {
		ProjectLogger.Info(message)
	} else {
		ProjectLogger.Error(message)
		os.Exit(ERROR_VALIDATION)
	}

	ProjectLogger.Exit(isValid)
	return nil
}

func Validate() (bool, error) {
	ProjectLogger.Enter()
	ProjectLogger.Trace(fmt.Sprintf("utils.Flags.InputFile: `%s`", utils.Flags.InputFile))

	// check for required fields on command
	if utils.Flags.InputFile == "" {
		return INVALID, fmt.Errorf("invalid input file: `%s` ", utils.Flags.InputFile)
	}

	document := schema.NewSbom(utils.Flags.InputFile)

	ProjectLogger.Info(fmt.Sprintf("Validating file `%s`...", utils.Flags.InputFile))

	// Load the raw, candidate SBOM (file) as JSON data
	document.UnmarshalSBOM() // i.e., utils.Flags.InputFile

	u, _ := log.FormatStruct("", document)
	fmt.Printf("%s\n", u)

	if utils.Flags.ForcedJsonSchemaFile != "" {

		document.SchemaInfo = *new(schema.SchemaInstance)
		document.SchemaInfo.File = utils.Flags.ForcedJsonSchemaFile
		ProjectLogger.Info(fmt.Sprintf("Schema file forced (i.e., `--force %s`)", utils.Flags.ForcedJsonSchemaFile))
	} else {

		// Search the document keys/values for known SBOM formats and schema
		errFind := document.FindFormatAndSchema()

		// Load schema based upon document declarations of schema format and version
		if errFind != nil {
			ProjectLogger.Error(errFind)
			return INVALID, errFind
		}
	}

	// TODO: support remote schema load (via URL) with a flag (default should always be local file for security)
	// TODO: support "latest" schema load (flag) for version (i.e., override version declared in document)
	var schemaURL = document.SchemaInfo.File
	ProjectLogger.Info(fmt.Sprintf("Loading schema `%s`...", schemaURL))
	schemaLoader := gojsonschema.NewReferenceLoader(schemaURL)

	// create a reusable schema object (to validate multiple documents)
	schema, err := gojsonschema.NewSchema(schemaLoader)

	if err != nil {
		ProjectLogger.Error(err)
		return INVALID, err
	}

	ProjectLogger.Info(fmt.Sprintf("Schema `%s` loaded.", schemaURL))

	// Create a JSON load for the actual document
	documentLoader := gojsonschema.NewReferenceLoader("file://" + utils.Flags.InputFile)

	result, errValidate := schema.Validate(documentLoader)
	ProjectLogger.Info(fmt.Sprintf("result.Valid(): `%t`.", result.Valid()))

	// Catch general errors from the validation module itself
	// Note: actual validation errors are in the `result` object
	if errValidate != nil {
		ProjectLogger.Error(errValidate)
		return INVALID, errValidate
	}

	// Log each validation result errors (i.e., actual validation errors found in the document)
	errs := result.Errors()
	lenErrs := len(errs)
	if lenErrs > 0 {
		ProjectLogger.Error(fmt.Sprintf("(%d) Schema errors detected:", lenErrs))
		for i, resultError := range errs {
			ProjectLogger.Error(fmt.Sprintf(">> %d. [%s] [%s]: \"%s\"",
				i+1,
				resultError.Type(),
				resultError.Field(),
				resultError.Description()))
		}
	}

	ProjectLogger.Exit(result.Valid())
	return result.Valid(), nil
}
