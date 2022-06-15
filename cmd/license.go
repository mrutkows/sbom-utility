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
	"os"
	"regexp"
	"strings"

	"github.com/jwangsadinata/go-multimap/slicemultimap"
	"github.com/mrutkows/sbom-utility/schema"
	"github.com/spf13/cobra"
)

const (
	SUBCOMMAND_LIST   = "list"
	SUBCOMMAND_POLICY = "policy"
)

var VALID_SUBCOMMANDS = []string{SUBCOMMAND_LIST, SUBCOMMAND_POLICY}

// LicenseChoice - Choice type
const (
	LC_TYPE_INVALID    = 0
	LC_TYPE_ID         = 1
	LC_TYPE_NAME       = 2
	LC_TYPE_EXPRESSION = 3
)

// Note: the SPDX spec. does not provide regex for an SPDX ID, but provides the following in ABNF:
//     dstring = 1*(ALPHA / DIGIT / "-" / "." )
// Currently, the regex below tests composition of of only
// alphanum, "-", and "." characters and disallows empty strings
// TODO:
// - First and last chars are not "-" or "."
// - Enforce reasonable min/.max length.
//   In theory, we can check overall length with positive lookahead
//   (e.g., min 3 max 128):  (?=.{3,128}$)
//   However, this does not appear to be supported in `regexp` package
//   or perhaps it must be a compiled expression TBD
const (
	REGEX_VALID_SPDX_ID = "^[a-zA-Z0-9.-]+$"
)

// compiled regexp. to save time
var spdxIdRegexp *regexp.Regexp

// Declare a fixed-sized array for LC type names
var LC_TYPE_NAMES = [...]string{"invalid", "id", "name", "exp"}

type LicenseInfo struct {
	LicenseChoiceType int
	LicenseChoice     CDXLicenseChoice
	Component         CDXComponent
}

var ComponentLicenses []LicenseInfo

var queryRequestComponents = QueryRequest{
	selectFieldsRaw: KEY_COMPONENTS,
	selectFields:    []string{KEY_COMPONENTS},
}

//var servicesLicenses []interface{} // TODO
var licenseMap = slicemultimap.New()
var licensePolicyMapByFamily = slicemultimap.New()
var licensePolicyMapById = slicemultimap.New()

func NewCommandLicense() *cobra.Command {
	getLogger().Enter()
	defer getLogger().Exit()
	var command = new(cobra.Command)
	command.Use = "license [subcommand] [flags]"
	command.Short = "Process licenses found in SBOM input file"
	command.Long = "Process licenses found in SBOM input file"
	command.RunE = licenseCmdImpl
	command.ValidArgs = VALID_SUBCOMMANDS
	command.PreRunE = func(cmd *cobra.Command, args []string) error {

		getLogger().Tracef("args: %v\n", args)

		if len(args) == 0 {
			return getLogger().Errorf("Missing required argument(s).")
		} else if len(args) > 1 {
			return getLogger().Errorf("Too many arguments provided. %v", args)
		}

		for _, cmd := range VALID_SUBCOMMANDS {
			if args[0] == cmd {
				getLogger().Tracef("Valid subcommand `%v` found", args[0])
				return nil
			}
		}
		return getLogger().Errorf("Argument provided is not valid: `%v`", args[0])
	}

	return command
}

func licenseCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter()
	defer getLogger().Exit()
	// No-op for now. The pre-check function should prevent this from being called
	getLogger().Tracef("NO-OP: Empty function")
	return nil
}

func hashLicenses(arrComponents []interface{}) error {
	getLogger().Enter()
	defer getLogger().Exit()
	for _, component := range arrComponents {
		uComp, errUnmarshal := UnMarshalComponent(component)

		if errUnmarshal != nil {
			return getLogger().Errorf("%s", errUnmarshal)
		}

		var licenseInfo LicenseInfo

		for _, licenseChoice := range uComp.Licenses {
			getLogger().Debugf("licenseChoice: %s", getLogger().FormatStruct(licenseChoice))

			licenseInfo.LicenseChoice = licenseChoice
			licenseInfo.Component = uComp

			if licenseChoice.License.Id != "" {
				licenseInfo.LicenseChoiceType = LC_TYPE_ID
				licenseMap.Put(licenseChoice.License.Id, licenseInfo)
			} else if licenseChoice.License.Name != "" {
				licenseInfo.LicenseChoiceType = LC_TYPE_NAME
				licenseMap.Put(licenseChoice.License.Name, licenseInfo)
			} else {
				if licenseChoice.Expression != "" {
					licenseInfo.LicenseChoiceType = LC_TYPE_EXPRESSION
					licenseMap.Put(licenseChoice.Expression, licenseInfo)
				} else {
					// NOTE: licenseInfo.LicenseChoiceType = 0 // invalid
					return getLogger().Errorf("invalid LicenseChoice for component: %v", uComp.Name)
				}

			}
		}
	}

	return nil
}

// "getter" for compiled regex expression
func getRegexForValidSpdxId() *regexp.Regexp {
	if spdxIdRegexp == nil {
		regex, err := regexp.Compile(REGEX_VALID_SPDX_ID)
		if err != nil {
			os.Exit(ERROR_APPLICATION)
		}
		spdxIdRegexp = regex
	}
	return spdxIdRegexp
}

func IsValidSpdxId(id string) bool {
	return getRegexForValidSpdxId().MatchString(id)
}

func IsValidFamilyKey(key string) bool {

	var BAD_KEYWORDS = []string{"CONFLICT", "UNKNOWN"}

	// For now, valid family keys are subsets of SPDX IDs
	// Therefore, pass result from that SPDX ID validation function
	valid := IsValidSpdxId(key)

	// Test for keywords that we have seen set that clearly are not valid family names
	// TODO: make configurable
	for _, keyword := range BAD_KEYWORDS {
		if strings.Contains(strings.ToLower(key), strings.ToLower(keyword)) {
			return false
		}
	}

	return valid
}

// NOTE: policy.Id == "" we allow as "valid" as this indicates a potential "family" entry (i.e., group of SPDX IDs)
func IsValidPolicyEntry(policy schema.LicensePolicy) bool {

	if policy.Id != "" && !IsValidSpdxId(policy.Id) {
		getLogger().Warningf("invalid SPDX ID: `%s` (Name=`%s`). Skipping...", policy.Id, policy.Name)
		return false
	}

	if strings.TrimSpace(policy.Name) == "" {
		getLogger().Warningf("invalid Name: `%s` (Id=`%s`).", policy.Name, policy.Id)
	}

	if !isValidUsagePolicy(policy.UsagePolicy) {
		getLogger().Warningf("invalid Usage Policy: `%s` (Id=`%s`, Name=`%s`). Skipping...", policy.UsagePolicy, policy.Id, policy.Name)
		return false
	}

	if !IsValidFamilyKey(policy.Family) {
		getLogger().Warningf("invalid Family: `%s` (Id=`%s`, Name=`%s`). Skipping...", policy.Family, policy.Id, policy.Name)
		return false
	}

	if policy.Id == "" {
		if len(policy.Children) < 1 {
			getLogger().Tracef("Family (policy): `%s`. Has no children (SPDX IDs) listed.", policy.Family)
		}
		// Test to make sure "family" entries (i.e. policy.Id == "") have valid "children" (SPDX IDs)
		for _, childId := range policy.Children {
			if !IsValidSpdxId(childId) {
				getLogger().Warningf("invalid Id: `%s` for Family: `%s`. Skipping...", childId, policy.Family)
				return false
			}
		}
	}

	// TODO - make sure policies with valid "Id" do NOT have children as these are
	// intended to be discrete (non-family-grouped) entries
	return true
}

// We will take the raw license policy list (data) and make it accessible for
// fast lookup via hash maps. Multiple hash maps are created understanding
// that license data in SBOMs can be based upon SPDX IDs <or> license names
// <or> license family names
// NOTE: we allow for both discrete policies based upon SPDX ID as well as
// "family" based policies.  This means given hash (lookup) might map to one or more
// family policies as well as a discrete one for specific SPDX ID.  In such cases,
// the policy MUST align (i.e., must not have both "allow" and "deny". Therefore,
// when we hash we assure that such a conflict does NOT exist at time of creation.
func hashPolicies(policies []schema.LicensePolicy) error {
	getLogger().Enter()
	defer getLogger().Exit()

	for _, policy := range policies {

		// ONLY hash valid policy records.
		if !IsValidPolicyEntry(policy) {
			// Do not add it to any hash table
			continue
		}

		// Only add to "id" hashmap if "Id" value is valid
		// NOTE: do NOT hash entries with "" (empty) Id values; however, they may represent a "family" entry
		if policy.Id != "" {
			getLogger().Tracef("ID Hashmap: Adding policy Id=`%s`, Name=`%s`, Family=`%s`", policy.Id, policy.Name, policy.Family)
			licensePolicyMapById.Put(policy.Id, policy)
		} else {
			getLogger().Tracef("Allowing Policy with `Id`==\"\" (empty) through")
		}

		// Assure we are not adding policy (value) to an existing hash
		// that represents a policy conflict.
		values, match := licensePolicyMapByFamily.Get(policy.Family)

		// If a hashmap entry exists, see if current policy matches those
		// already added for that key
		if match {
			getLogger().Tracef("Family Hashmap: Entries exist for policy Id=`%s`, Name=`%s`, Family=`%s`", policy.Id, policy.Name, policy.Family)
			consistent := verifyPoliciesMatch(policy, values)

			if !consistent {
				getLogger().Warningf("Multiple (possibly conflicting) policies declared for ID `%s`,family: `%s`, policy: `%s`",
					policy.Id,
					policy.Family,
					policy.UsagePolicy)
				os.Exit(ERROR_VALIDATION)
			}
		}

		// NOTE: validation of policy struct (including "family" value) is done above
		getLogger().Tracef("Family Hashmap: Adding policy Id=`%s`, Name=`%s`, Family=`%s`", policy.Id, policy.Name, policy.Family)
		licensePolicyMapByFamily.Put(policy.Family, policy)
	}

	return nil
}

// given an array of policies verify their "usage" policy does not represent a conflict
func verifyPoliciesMatch(testPolicy schema.LicensePolicy, policies []interface{}) bool {

	var currentPolicy schema.LicensePolicy
	testUsagePolicy := testPolicy.UsagePolicy

	for _, current := range policies {
		currentPolicy = current.(schema.LicensePolicy)
		getLogger().Tracef("Usage Policy=%s", currentPolicy.UsagePolicy)

		if currentPolicy.UsagePolicy != testUsagePolicy {
			getLogger().Warningf("Policy (Id: %s, Family: %s, Policy: %s) is in conflict with policies (%s) declared in the same family.",
				currentPolicy.Id,
				currentPolicy.Family,
				currentPolicy.UsagePolicy,
				testUsagePolicy)
			// TODO: uncomment once the master policy data removes an "?" question marks
			// NOTE: Exiting here may no longer be need or desirable as we SHOULD no longer hash conflicts
			//os.Exit(ERROR_VALIDATION)
		}
	}

	return true
}
