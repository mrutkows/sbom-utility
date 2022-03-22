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

	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// Supported list type
const (
	LIST_TYPE_COMPONENT = "component" // functionality in "license", just needs to be made as separate path
	LIST_TYPE_LICENSE   = "license"   // TODO: separate "component" list and use as input to "license" or other lists within component
	LIST_TYPE_COPYRIGHT = "copyright" // TODO: support listing of all copyrights (leverage "license" code)
)

var SUPPORTED_LIST_TYPES = []string{LIST_TYPE_COMPONENT, LIST_TYPE_LICENSE, LIST_TYPE_COPYRIGHT}

var listCmd = &cobra.Command{
	Use:   "list <object type> -i <SBOM (JSON) input file relative location>",
	Short: "create a list of <object type> from an SBOM input",
	Long:  "create a list of <object type> from an SBOM input",
	RunE:  listCmdImpl,
	Args: func(cmd *cobra.Command, args []string) error {
		if len(args) < 1 {
			return getLogger().Errorf("Missing list type (e.g., \"license\")")
		} else if len(args) > 1 {
			return getLogger().Errorf("Only a single list type is currently supported")
		}
		return nil
	},
}

func init() {
	getLogger().Enter()
	// Add local flags to command
	rootCmd.AddCommand(listCmd)
	getLogger().Exit()
}

func listCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter()
	// No-op for now
	// TODO: use Cobra to see if we can enforce at least one subcommand to be present
	// <and/or> produce custom help here letting user know subcommand usage/purpose
	err := licenseCmdImpl(cmd, args, LIST_TYPE_LICENSE)

	getLogger().Exit()
	return err
}

// NOTE: default license list SHOULD be component only
// NOTE: default behavior is to include all components regardless of appearance in dependencies list
// TODO: extended license list should include "tools" and "services"
func licenseCmdImpl(cmd *cobra.Command, args []string, listType string) error {
	getLogger().Enter()

	// Note: returns error if either file load or unmarshal to JSON map fails
	document, errLoad := LoadInputFileAndUnmarshal()

	if errLoad != nil {
		getLogger().Error(errLoad)
		return errLoad
	}

	//datapath := []string{"components"}
	var queryRequest QueryRequest
	queryRequest.selectFieldsRaw = "components"
	queryRequest.selectFields = []string{"components"}

	// allocate response/result object
	var response = new(QueryResult)

	iComponents, errComponents := query(document.GetMap(), &queryRequest, response)

	if errComponents != nil {
		getLogger().Error(errComponents)
		return errComponents
	}

	// cast to a generic interface type array
	arrComponents, ok := iComponents.([]interface{})

	// loop through comps. to get licenses
	if ok && len(arrComponents) > 0 {
		tempLicenses := make([]interface{}, 0, len(arrComponents))
		getLogger().Trace(fmt.Sprintf("tempLicenses.(type): (%T)\n", tempLicenses))

		for i, component := range arrComponents {
			tempMap := component.(map[string]interface{})
			getLogger().Trace(fmt.Sprintf("Looking for licenses in component[%d]:\n%v\n", i, tempMap))
			tempLicenses = append(tempLicenses, tempMap["licenses"])
		}
		jsonLicenses, _ := utils.ConvertMapToJson("", tempLicenses)

		// Output the JSON data directly to stdout (not subject to log-level)
		getLogger().Info(fmt.Sprintf("`list %s` result:", listType))
		fmt.Printf("%s\n", jsonLicenses)

	} else {
		return getLogger().Errorf("no components found in document at path: %v", queryRequest.selectFieldsRaw)
	}

	getLogger().Exit()
	return nil
}
