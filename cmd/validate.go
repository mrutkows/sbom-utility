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

func init() {
	ProjectLogger.Enter()
	rootCmd.AddCommand(validateCmd)
	ProjectLogger.Exit()
}

var validateCmd = &cobra.Command{
	Use:   "validate -i <input-sbom.json>",
	Short: "validate input file against its declared SBOM schema.",
	Long:  "validate input file against its declared SBOM schema, if detectable and supported.",
	Run: func(cmd *cobra.Command, args []string) {
		ProjectLogger.Enter()
		// TODO: remove when execution call order satisfactory
		fmt.Println("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
		ProjectLogger.Exit()
	},
	RunE: validateCmdImpl,
}

func validateCmdImpl(cmd *cobra.Command, args []string) error {
	ProjectLogger.Enter()
	isValid, err := Validate()
	if err != nil {
		ProjectLogger.Error(err)
		os.Exit(-3)
	}
	ProjectLogger.Info(fmt.Sprintf("Document %s: valid=[%t]", utils.Flags.InputFile, isValid))
	ProjectLogger.Exit()
	return nil
}

func Validate() (bool, error) {
	ProjectLogger.Enter()

	document := schema.NewSbom()
	ProjectLogger.Info(fmt.Sprintf("Validating file [%s]...\n", utils.Flags.InputFile))
	document.UnmarshalSBOM(utils.Flags.InputFile)

	u, _ := log.FormatStruct("", document)
	fmt.Printf("%s\n", u)

	loader := gojsonschema.NewReferenceLoader(schema.SCHEMA_SPDX_2_2_2_LOCAL)

	// create a reusable schema object (to validate multiple documents)
	_, err := gojsonschema.NewSchema(loader)

	if err != nil {
		ProjectLogger.Error(err)
		return false, err
	}
	ProjectLogger.Exit(true)
	return true, nil
}

// func unMarshallSBOM(filename string) error {
// 	// Open our jsonFile
// 	var fullFilename = filename
// 	// Conditionally append working directory if no abs. path detected
// 	if len(filename) > 0 && filename[0] != '/' {
// 		fullFilename = utils.Flags.WorkingDir + "/" + filename
// 	}
// 	jsonFile, err := os.Open(fullFilename)
// 	// if we os.Open returns an error then handle it
// 	if err != nil {
// 		cmdlogger.Error(err)
// 		os.Exit(-1)
// 	}
// 	cmdlogger.Info(fmt.Sprintf("Successfully Opened: `%s`", filename))

// 	// defer the closing of our jsonFile so that we can parse it later on
// 	defer jsonFile.Close()

// 	// read our opened jsonFile as a byte array.
// 	rawBytes, _ := ioutil.ReadAll(jsonFile)

// 	// Declared an empty map interface
// 	var result map[string]interface{}

// 	// Unmarshal or Decode the JSON to the interface.
// 	errUnmarshal := json.Unmarshal([]byte(rawBytes), &result)
// 	if errUnmarshal != nil {
// 		cmdlogger.Error(errUnmarshal)
// 	}

// 	spdxVersion := result["spdxVersion"].(string)
// 	cmdlogger.Trace(fmt.Sprintf("spdxVersion=`%s`", spdxVersion))

// 	// Print the data type of result variable
// 	cmdlogger.Debug(fmt.Sprintf("%s\n", reflect.TypeOf(result)))

// 	return nil
// }
