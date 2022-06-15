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
	"reflect"
	"strings"
	"text/tabwriter"

	"github.com/mrutkows/sbom-utility/schema"
	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// Subcommand flags
const (
	FLAG_POLICY_OUTPUT_FORMAT_HELP = "Format output using the specific type. Valid values: \"txt\", \"csv\""
)

const (
	POLICY_ALLOW     = "allow"
	POLICY_DENY      = "deny"
	POLICY_UNMATCHED = "UNMATCHED"
)

var VALID_USAGE_POLICIES = []string{POLICY_ALLOW, POLICY_DENY}

// WARNING: Cobra will not recognize a subcommand if its `command.Use` is not a single
// word string that matches one of the `command.ValidArgs` set on the parent command
func NewCommandPolicy() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = "policy"
	command.Short = "List policies associated with known licenses"
	command.Long = "List caller-supplied, \"allow/deny\"-style policies associated with known software, hardware or data licenses"
	command.Flags().StringVarP(&utils.Flags.OutputFormat, FLAG_FILE_OUTPUT_FORMAT, "", "", FLAG_POLICY_OUTPUT_FORMAT_HELP)
	command.RunE = func(cmd *cobra.Command, args []string) error {
		var writer io.Writer = os.Stdout
		var err error
		getLogger().Enter()
		defer getLogger().Exit()

		if utils.Flags.OutputFile != "" {

			getLogger().Infof("Creating output file: `%s`; output format: `%s`",
				utils.Flags.OutputFile,
				utils.Flags.OutputFormat)

			var oFile *os.File
			//writer = os.OpenFile(utils.Flags.OutputFile,os.O_CREATE,O)
			oFile, err = os.Create(utils.Flags.OutputFile)

			if err != nil {
				getLogger().Error(err)
			}
			writer = oFile
			defer oFile.Close()
		}

		switch utils.Flags.OutputFormat {
		case "":
			// defaults to text if no explicit `--format` parameter
			err = DisplayLicensePolicies(writer)
		case "txt":
			err = DisplayLicensePolicies(writer)
		case "csv":
			err = DisplayLicensePoliciesCSV(writer)
		default:
			getLogger().Warningf("Unsupported format: `%s`; using default format.",
				utils.Flags.OutputFormat)
			err = DisplayLicensePolicies(writer)
		}
		return err
	}
	return command
}

func isValidUsagePolicy(usagePolicy string) bool {
	for _, entry := range VALID_USAGE_POLICIES {
		if usagePolicy == entry {
			return true
		}
	}
	return false
}

func FindPolicyBySpdxId(id string) (policyValue string, matchedPolicy schema.LicensePolicy) {
	getLogger().Enter("id:", id)
	defer getLogger().Exit()

	var matched bool
	var arrPolicies []interface{}

	arrPolicies, matched = licensePolicyMapById.Get(id)
	getLogger().Tracef("licensePolicyMapById.Get(%s): (%v) matches", id, len(arrPolicies))

	// There MUST be ONLY one policy per (discrete) license ID
	if len(arrPolicies) > 1 {
		getLogger().Errorf("Multiple (possibly conflicting) policies declared for SPDX ID=`%s`", id)
		os.Exit(ERROR_VALIDATION)
	}

	if matched {
		matchedPolicy = arrPolicies[0].(schema.LicensePolicy)
		policyValue = matchedPolicy.UsagePolicy
	} else {
		getLogger().Tracef("No policy match found for SPDX ID=`%s` ", id)
		policyValue = POLICY_UNMATCHED
	}

	return policyValue, matchedPolicy
}

// NOTE: for now, we will look for the "family" name encoded in the License.Name field
// (until) we can get additional fields/properties added to the CDX LicenseChoice schema
func FindPolicyByFamilyName(name string) (policyValue string, matchedPolicy schema.LicensePolicy) {
	getLogger().Enter("name:", name)
	defer getLogger().Exit()

	var matched bool
	var key string
	var arrPolicies []interface{}

	// See if any of the policy family keys contain the family name
	matched, key = searchForLicenseFamilyName(name)

	if matched {
		arrPolicies, _ = licensePolicyMapByFamily.Get(key)

		if arrPolicies == nil {
			getLogger().Errorf("No policy match found in hashmap for family name key: `%s`", key)
			os.Exit(ERROR_APPLICATION)
		}

		// NOTE: We can use the first policy (of a family) as they are
		// verified to be consistent when loaded from the policy config. file
		matchedPolicy = arrPolicies[0].(schema.LicensePolicy)
		policyValue = matchedPolicy.UsagePolicy

		// TODO: verify conflict or not
		if len(arrPolicies) > 1 {
			getLogger().Warningf("Multiple (possibly conflicting) policies declared for license family name=`%s` ", key)
			//os.Exit(ERROR_VALIDATION)
		}
	} else {
		getLogger().Tracef("No policy match found for license family name=`%s` ", name)
		policyValue = POLICY_UNMATCHED
	}

	return policyValue, matchedPolicy
}

func FindPolicy(licenseInfo LicenseInfo) (matchedPolicy schema.LicensePolicy) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Initialize to empty
	matchedPolicy = schema.LicensePolicy{}

	switch licenseInfo.LicenseChoiceType {
	case LC_TYPE_ID:
		matchedPolicy.UsagePolicy, matchedPolicy = FindPolicyBySpdxId(licenseInfo.LicenseChoice.License.Id)
	case LC_TYPE_NAME:
		matchedPolicy.UsagePolicy, matchedPolicy = FindPolicyByFamilyName(licenseInfo.LicenseChoice.License.Name)
	case LC_TYPE_EXPRESSION:
		// Parse expression according to SPDX spec.
		expressionTree := parseExpression(licenseInfo.LicenseChoice.Expression)
		getLogger().Debugf("Parsed expression:\n%v", expressionTree)
		matchedPolicy.UsagePolicy = expressionTree.CompoundUsagePolicy
	}
	return
}

// Looks for an SPDX family (name) somewhere in the CDX License object "Name" field
func containsFamilyName(name string, familyName string) bool {
	// NOTE: we do not currently normalize as we assume family names
	// are proper substring of SPDX IDs which are mixed case and
	// should match exactly as encoded.
	return strings.Contains(name, familyName)
}

// Loop through all known license family names (in hashMap) to see if any
// appear in the CDX License "Name" field
func searchForLicenseFamilyName(licenseName string) (bool, string) {
	getLogger().Enter()
	defer getLogger().Exit()

	keys := licensePolicyMapByFamily.Keys()
	var familyName string

	for _, key := range keys {
		familyName = key.(string)

		// TODO: remove once license.json file is cleaned up
		if familyName == "?" {
			continue
		}

		getLogger().Debugf("Searching for familyName: '%s' in License Name: %s", familyName, licenseName)

		found := containsFamilyName(licenseName, familyName)

		if found {
			getLogger().Tracef("Match found: familyName: '%s' in License Name: %s", familyName, licenseName)
			return found, familyName
		}
	}

	return false, ""
}

// Helper function in case displayed table columns become too wide
func truncateString(value string, maxLength int) string {
	if len(value) > maxLength {
		value = value[:maxLength]
	}
	return value
}

// TODO: Allow caller to pass flag to truncate or not (perhaps with value)
func DisplayLicensePolicies(output io.Writer) error {
	getLogger().Enter()
	defer getLogger().Exit()

	// See if we have a non-empty license policy config struct
	// NOTE: This should be caught on "file load"
	if reflect.DeepEqual(schema.LicensePolicyConfig, schema.EMPTY_LicenseComplianceConfig) {
		err := getLogger().Errorf("license policy is empty; verify license configuration file `%s` is loaded.", DEFAULT_LICENSE_POLICIES)
		return err
	}

	// initialize tabwriter
	w := new(tabwriter.Writer)

	// minwidth, tabwidth, padding, padchar, flags
	w.Init(output, 8, 2, 2, ' ', 0)
	defer w.Flush()

	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", "Policy", "Family", "SPDX ID", "Name", "Notes")
	fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", "------", "------", "-------", "----", "-----")
	list := schema.LicensePolicyConfig.PolicyList

	for _, policy := range list {
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
			policy.UsagePolicy,
			truncateString(policy.Family, 16),
			policy.Id,
			truncateString(policy.Name, 16),
			truncateString(strings.Join(policy.Notes, ", "), 32))
	}

	fmt.Fprintf(w, "\n")
	return nil
}

func DisplayLicensePoliciesCSV(output io.Writer) error {
	getLogger().Enter()
	defer getLogger().Exit()

	// See if we have a non-empty license policy config struct
	// NOTE: This should be caught on "file load"
	if reflect.DeepEqual(schema.LicensePolicyConfig, schema.EMPTY_LicenseComplianceConfig) {
		err := getLogger().Errorf("license policy is empty; verify license configuration file `%s` is loaded.", DEFAULT_LICENSE_POLICIES)
		return err
	}

	// initialize writer and prepare the list of entries (i.e., the "rows")
	w := csv.NewWriter(output)
	var line []string
	list := schema.LicensePolicyConfig.PolicyList
	titles := []string{"Policy", "Family", "SPDX ID", "Name", "Annotations", "Notes"}

	if err := w.Write(titles); err != nil {
		return getLogger().Errorf("error writing record to csv (%v): %s", output, err)
	}

	for _, policy := range list {
		line = nil
		line = append(line,
			policy.UsagePolicy,
			policy.Family,
			policy.Id,
			policy.Name,
			strings.Join(policy.AnnotationRefs, ", "),
			strings.Join(policy.Notes, ", "))

		if err := w.Write(line); err != nil {
			getLogger().Errorf("csv.Write: %w", err)
		}
	}

	w.Flush()
	return nil
}
