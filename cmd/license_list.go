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
	"encoding/csv"
	"fmt"
	"io"
	"os"
	"text/tabwriter"

	"github.com/mrutkows/sbom-utility/log"
	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// Subcommand flags
const (
	FLAG_LICENSE_SUMMARY = "summary"
)

// Query command flag help messages
const (
	FLAG_LICENSE_SUMMARY_HELP    = "Summarize licenses and component references in table format"
	FLAG_LIST_OUTPUT_FORMAT_HELP = "Format output using the specific type. Valid values: \"json\""
)

// WARNING: Cobra will not recognize a subcommand if its `command.Use` is not a single
// word string that matches one of the `command.ValidArgs` set on the parent command
func NewCommandList() *cobra.Command {
	getLogger().Enter()
	defer getLogger().Exit()
	var command = new(cobra.Command)
	command.Use = "list"
	//command.Use = "license list -i <SBOM (JSON) input file relative location> [flags]"
	command.Short = "List licenses found in SBOM input file"
	command.Long = "List licenses found in SBOM input file"
	command.Flags().StringVarP(&utils.Flags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", "", FLAG_LIST_OUTPUT_FORMAT_HELP)
	command.Flags().Bool(FLAG_LICENSE_SUMMARY, false, FLAG_LICENSE_SUMMARY_HELP)
	command.RunE = listCmdImpl
	return (command)
}

// NOTE: The license command ONLY WORKS on CDX format
// NOTE: For now, default license list SHOULD be component only
//       default behavior is to include all components regardless of appearance in dependencies list
// TODO: extended license list should include "services"
func listCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter(args)
	defer getLogger().Exit()

	bSummary, _ := cmd.Flags().GetBool(FLAG_LICENSE_SUMMARY)

	var writer io.Writer = os.Stdout
	var err error
	getLogger().Enter()
	defer getLogger().Exit()

	if utils.Flags.OutputFile != "" {

		getLogger().Infof("Creating output file: `%s`; output format: `%s`",
			utils.Flags.OutputFile,
			utils.Flags.OutputFormat)

		var oFile *os.File
		oFile, err = os.Create(utils.Flags.OutputFile)

		if err != nil {
			getLogger().Error(err)
		}
		writer = oFile
		defer oFile.Close()
	}

	err = ListLicenses(writer, utils.Flags.OutputFormat, bSummary)

	return err
}

func ListLicenses(output io.Writer, format string, summary bool) error {
	// Note: returns error if either file load or unmarshal to JSON map fails
	document, errLoad := LoadInputFileAndUnmarshal()

	if errLoad != nil {
		getLogger().Error(errLoad)
		return errLoad
	}

	// allocate response/result object
	var response = new(QueryResponse)
	mapComponents, errQuery := queryMap(document.GetMap(), &queryRequestComponents, response)

	if errQuery != nil {
		return errQuery
	}

	if len(mapComponents) == 0 {
		return getLogger().Errorf("no components found in document at path: %v", queryRequestComponents.selectFieldsRaw)
	}

	// TODO: Create a format (schema) agnostic interface for retrieving commonly used elements
	// from an SBOM such as "components" (can use CDX terminology)
	arrComponents := mapComponents[KEY_COMPONENTS].([]interface{})

	errHash := hashLicenses(arrComponents)
	if errHash != nil {
		return errHash
	}

	if summary {
		if format == "csv" {
			DisplayLicenseListSummaryCSV(output)
		} else {
			DisplayLicenseListSummary(output)
		}
	} else {
		// default is (raw) JSON
		DisplayLicenseListJson(output)
	}

	return nil
}

// TODO: Support de-duplication of license records (MUST be exact using deep comparison)
func DisplayLicenseListJson(output io.Writer) {
	getLogger().Enter()
	defer getLogger().Exit()

	var licenseInfo LicenseInfo
	var lc []CDXLicenseChoice

	for _, licenseName := range licenseMap.KeySet() {
		arrLicenseInfo, _ := licenseMap.Get(licenseName)

		for _, iInfo := range arrLicenseInfo {
			licenseInfo = iInfo.(LicenseInfo)
			lc = append(lc, licenseInfo.LicenseChoice)
			json, _ := log.FormatInterfaceAsJson(lc)
			fmt.Fprintf(output, "%s\n", json)
		}
	}
}

func DisplayLicenseListSummary(output io.Writer) {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize tabwriter
	w := new(tabwriter.Writer)

	// minwidth, tabwidth, padding, padchar, flags
	w.Init(output, 8, 2, 2, ' ', 0)
	defer w.Flush()

	var licenseInfo LicenseInfo

	fmt.Fprintf(w, "\n%s\t%s\t%s\t%s\t%s", "Policy", "Type", "ID/Name/Expression", "Component(s)", "Package URL (pURL)")
	fmt.Fprintf(w, "\n%s\t%s\t%s\t%s\t%s", "------", "----", "------------------", "------------", "------------------")

	for _, licenseName := range licenseMap.KeySet() {
		arrLicenseInfo, _ := licenseMap.Get(licenseName)

		// An SBOM SHOULD always contain at least 1 (declared) license
		if len(arrLicenseInfo) == 0 {
			getLogger().Errorf("SBOM contained 0 (zero) component licenses")
			os.Exit(ERROR_VALIDATION)
		}

		for _, iInfo := range arrLicenseInfo {
			licenseInfo = iInfo.(LicenseInfo)
			policy := FindPolicy(licenseInfo)

			getLogger().Tracef("%s\t%v\t%s\t%s\t%s",
				policy.UsagePolicy,
				LC_TYPE_NAMES[licenseInfo.LicenseChoiceType],
				licenseName,
				licenseInfo.Component.Name,
				licenseInfo.Component.Purl)

			fmt.Fprintf(w, "\n%s\t%v\t%s\t%s\t%s",
				policy.UsagePolicy,
				LC_TYPE_NAMES[licenseInfo.LicenseChoiceType],
				licenseName,
				licenseInfo.Component.Name,
				licenseInfo.Component.Purl)
		}
	}

	fmt.Fprintf(w, "\n")
}

func DisplayLicenseListSummaryCSV(output io.Writer) error {
	getLogger().Enter()
	defer getLogger().Exit()

	// initialize writer and prepare the list of entries (i.e., the "rows")
	w := csv.NewWriter(output)
	var line []string
	var licenseInfo LicenseInfo

	titles := []string{"Policy", "Type", "ID/Name/Expression", "Component(s)", "Package URL (pURL)"}

	if err := w.Write(titles); err != nil {
		return getLogger().Errorf("error writing record to csv (%v): %s", output, err)
	}

	for _, licenseName := range licenseMap.KeySet() {
		arrLicenseInfo, _ := licenseMap.Get(licenseName)

		// An SBOM SHOULD always contain at least 1 (declared) license
		if len(arrLicenseInfo) == 0 {
			getLogger().Errorf("SBOM contained 0 (zero) component licenses")
			os.Exit(ERROR_VALIDATION)
		}

		for _, iInfo := range arrLicenseInfo {

			licenseInfo = iInfo.(LicenseInfo)
			policy := FindPolicy(licenseInfo)

			line = nil
			line = append(line,
				policy.UsagePolicy,
				LC_TYPE_NAMES[licenseInfo.LicenseChoiceType],
				licenseName.(string),
				licenseInfo.Component.Name,
				licenseInfo.Component.Purl)

			if err := w.Write(line); err != nil {
				getLogger().Errorf("csv.Write: %w", err)
			}
		}
	}

	w.Flush()
	return nil
}
