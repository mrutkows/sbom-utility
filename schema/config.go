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
	"fmt"
	"io/ioutil"

	"github.com/mrutkows/sbom-utility/utils"
)

const (
	USAGE_POLICY_UNDEFINED   = ""
	USAGE_POLICY_ALLOW       = "allow"
	USAGE_POLICY_DENY        = "deny"
	USAGE_POLICY_CONDITIONAL = "conditional"
)

type LicensePolicy struct {
	Id             string   `json:"id"`
	Family         string   `json:"family"`
	Name           string   `json:"name"`
	UsagePolicy    string   `json:"usagePolicy"`
	Children       []string `json:"children"`
	Notes          []string `json:"notes"`
	Urls           []string `json:"urls"`
	AnnotationRefs []string `json:"annotationRefs"`
}

type LicenseComplianceConfig struct {
	PolicyList  []LicensePolicy   `json:"policies"`
	Annotations map[string]string `json:"annotations"`
}

var LicensePolicyConfig LicenseComplianceConfig
var EMPTY_LicenseComplianceConfig LicenseComplianceConfig = LicenseComplianceConfig{}

func LoadFormatBasedSchemas(filename string) error {
	ProjectLogger.Enter()
	defer ProjectLogger.Exit()

	var cfgFilename string

	// validate filename
	if len(filename) == 0 {
		return fmt.Errorf("config: invalid filename: `%s`", filename)
	}

	// Conditionally append working directory if no abs. path detected
	if len(filename) > 0 && filename[0] != '/' {
		cfgFilename = utils.Flags.WorkingDir + "/" + filename
	} else {
		cfgFilename = filename
	}

	buffer, err := ioutil.ReadFile(cfgFilename)
	if err != nil {
		return fmt.Errorf("config: unable to `ReadFile`: `%s`", cfgFilename)
	}

	err = json.Unmarshal(buffer, &KnownSchemas)
	if err != nil {
		return fmt.Errorf("config: cannot `Unmarshal`: `%s`", cfgFilename)
	}

	// TODO: validate ONLY ONE schema per-minor version is marked `latest`
	// NOTE: There MAY be 2 "latest" for those that have "strict" flag (true) supported
	return nil
}

func LoadLicensePolicies(filename string) error {
	ProjectLogger.Enter()
	defer ProjectLogger.Exit()

	var cfgFilename string

	// validate filename
	if len(filename) == 0 {
		return fmt.Errorf("config: invalid filename: `%s`", filename)
	}

	// Conditionally append working directory if no abs. path detected
	if len(filename) > 0 && filename[0] != '/' {
		cfgFilename = utils.Flags.WorkingDir + "/" + filename
	} else {
		cfgFilename = filename
	}

	// we unmarshal our byteArray which contains our
	// jsonFile's content into 'users' which we defined above
	buffer, err := ioutil.ReadFile(cfgFilename)

	if err != nil {
		return fmt.Errorf("config: unable to `ReadFile`: `%s`", cfgFilename)
	}

	errUnmarshal := json.Unmarshal(buffer, &LicensePolicyConfig)
	if errUnmarshal != nil {
		return fmt.Errorf("config: cannot `Unmarshal`: `%s`", cfgFilename)
	}

	// TODO: validate ONLY ONE schema per-minor version is marked `latest`
	// NOTE: There MAY be 2 "latest" for those that have "strict" flag (true) supported
	return nil
}
