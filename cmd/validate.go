package cmd

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"reflect"

	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
	"github.com/xeipuuv/gojsonschema"
)

// https://github.com/spdx/spdx-spec/blob/master/schemas/spdx-schema.json
// https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3.schema.json
// https://github.com/CycloneDX/specification/blob/master/schema/bom-1.3-strict.schema.json
const (
	SCHEMA_SPDX_2_2_2_LOCAL           = "file://schema/spdx/2.2/spdx-schema.json"
	SCHEMA_CYCLONEDX_1_3_LOCAL        = "file://schema/cyclonedx/1.3/bom-1.3.schema.json"
	SCHEMA_CYCLONEDX_1_3_STRICT_LOCAL = "file://schema/cyclonedx/1.3/bom-1.3-strict.schema.json"
)

var (
	supportedSchemas = []string{SCHEMA_SPDX_2_2_2_LOCAL, SCHEMA_CYCLONEDX_1_3_LOCAL, SCHEMA_CYCLONEDX_1_3_STRICT_LOCAL}
)

func init() {
	loggers.Enter()
	rootCmd.AddCommand(validateCmd)
	loggers.Exit()
}

var validateCmd = &cobra.Command{
	Use:   "validate",
	Short: "validate input file's schema",
	Long:  "validate -i <input-sbom.json>",
	Run: func(cmd *cobra.Command, args []string) {
		loggers.Enter()
		// schema := SCHEMA_SPDX_2_2_2_LOCAL
		// Validate(schema, "")
		loggers.Exit()
	},
	RunE: validateCmdImpl,
}

func validateCmdImpl(cmd *cobra.Command, args []string) error {
	loggers.Enter()
	schema := SCHEMA_SPDX_2_2_2_LOCAL
	Validate(schema, "")
	loggers.Exit()
	return nil
}

func unMarshallSBOM(filename string) error {

	// Open our jsonFile
	var fullFilename = filename
	// Conditionally append working directory if no abs. path detected
	if len(filename) > 0 && filename[0] != '/' {
		fullFilename = utils.Flags.WorkingDir + "/" + filename
	}
	jsonFile, err := os.Open(fullFilename)

	// if we os.Open returns an error then handle it
	if err != nil {
		loggers.ExitError(err)
		os.Exit(-1)
	}

	loggers.Info(fmt.Sprintf("Successfully Opened: `%s`", filename))

	// defer the closing of our jsonFile so that we can parse it later on
	defer jsonFile.Close()

	// read our opened jsonFile as a byte array.
	rawBytes, _ := ioutil.ReadAll(jsonFile)

	// Declared an empty map interface
	var result map[string]interface{}

	// Unmarshal or Decode the JSON to the interface.
	errUnmarshal := json.Unmarshal([]byte(rawBytes), &result)
	if errUnmarshal != nil {
		loggers.Error(errUnmarshal)
	}

	spdxVersion := result["spdxVersion"].(string)
	loggers.Trace(fmt.Sprintf("spdxVersion=`%s`", spdxVersion))

	// Print the data type of result variable
	loggers.Debug(fmt.Sprintf("%s\n", reflect.TypeOf(result)))

	return nil
}

func isSchemaSupported(schema string) bool {
	loggers.Enter()
	for _, s := range supportedSchemas {

		if schema == s {
			return true
		}
	}
	loggers.Exit()
	return false
}

func Validate(schema string, document string) (bool, error) {
	loggers.Enter()
	if !isSchemaSupported(schema) {
		return false, fmt.Errorf("schema [%s] not supported", schema)
	}

	unMarshallSBOM(utils.Flags.InputFile)

	loader := gojsonschema.NewReferenceLoader(SCHEMA_SPDX_2_2_2_LOCAL)

	// create a reusable schema object (to validate multiple documents)
	_, err := gojsonschema.NewSchema(loader)

	if err != nil {
		loggers.ExitError(err)
		return false, err
	}
	loggers.Exit()
	return true, nil
}
