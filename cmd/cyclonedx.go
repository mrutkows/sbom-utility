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
	"encoding/json"
)

const (
	KEY_METADATA   = "metadata"
	KEY_COMPONENTS = "components"
	KEY_LICENSES   = "licenses"
)

// For convenience, we provide named vars. for testing for zero-length (empty) structs
var EMPTY_CDXLicense = CDXLicense{}

// NOTE: These structure are coded to the 1.3 schema, 1.4 field are ignored for now
type CDXBom struct {
	BomFormat          string                 `json:"bomFormat"`
	SpecVersion        string                 `json:"specVersion"`
	SerialNumber       string                 `json:"serialNumber"`
	Version            string                 `json:"version"`
	Metadata           CDXMetadata            `json:"metadata"`
	Components         []CDXComponent         `json:"components"`
	Services           []CDXService           `json:"services"`
	Dependencies       []CDXDependency        `json:"dependencies"`
	ExternalReferences []CDXExternalReference `json:"externalReferences"`
	Compositions       []CDXComposition       `json:"compositions"`
}

type CDXMetadata struct {
	Timestamp    string                     `json:"timestamp"`
	Tools        []CDXTool                  `json:"tools"`
	Authors      []CDXOrganizationalContact `json:"authors"`
	Manufacturer CDXOrganizationalEntity    `json:"manufacturer"`
	Supplier     CDXOrganizationalEntity    `json:"supplier"`
	Component    CDXComponent               `json:"component"`
	Hashes       []CDXHash                  `json:"hashes"`
	Licenses     []CDXLicenseChoice         `json:"licenses"`
	Properties   []CDXProperty              `json:"properties"`
}

type CDXTool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CDXComponent struct {
	Purl               string                     `json:"purl"`
	BomRef             string                     `json:"bom-ref"`
	Type               string                     `json:"type"`
	MimeType           string                     `json:"mime-type"`
	Name               string                     `json:"name"`
	Version            string                     `json:"version"`
	Description        string                     `json:"description"`
	Copyright          string                     `json:"copyright"`
	Publisher          string                     `json:"publisher"`
	Group              string                     `json:"group"`
	Scope              string                     `json:"scope"`
	Modified           bool                       `json:"modified"`
	Manufacturer       CDXOrganizationalEntity    `json:"manufacturer"`
	Supplier           CDXOrganizationalEntity    `json:"supplier"`
	Licenses           []CDXLicenseChoice         `json:"licenses"`
	Hashes             []CDXHash                  `json:"hashes"`
	Author             []CDXOrganizationalContact `json:"author"`
	ExternalReferences []CDXExternalReference     `json:"externalReferences"`
	Properties         []CDXProperty              `json:"properties"`
	Components         []CDXComponent             `json:"components"`
	// TODO: pedigree
	// TODO: evidence
	// Deprecated
	Cpe  string `json:"cpe"`
	Swid string `json:"swid"`
}

type CDXService struct {
	BomRef      string `json:"bom-ref"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type CDXDependency struct {
	Ref       string `json:"ref"`
	DependsOn string `json:"dependsOn"`
}

type CDXComposition struct {
	Aggregate    string   `json:"aggregate"`
	Assemblies   []string `json:"assemblies"`
	Dependencies []string `json:"dependencies"`
}

type CDXHash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

// NOTE: "oneOf": ["license", "expression"] is required
type CDXLicenseChoice struct {
	License    CDXLicense `json:"license"`
	Expression string     `json:"expression"`
}

// NOTE: "oneOf": ["id", "name"] is required
type CDXLicense struct {
	Id   string        `json:"id"`
	Name string        `json:"name"`
	Text CDXAttachment `json:"text"`
	Url  string        `json:"url"`
}

type CDXAttachment struct {
	ContentType string `json:"contentType"`
	Encoding    string `json:"encoding"`
	Content     string `json:"content"`
}

type CDXExternalReference struct {
	Url     string    `json:"url"`
	Type    string    `json:"type"`
	Comment string    `json:"comment"`
	Hashes  []CDXHash `json:"hashes"`
}

type CDXOrganizationalEntity struct {
	Name    string                     `json:"name"`
	Url     []string                   `json:"url"`
	Contact []CDXOrganizationalContact `json:"contact"`
}

type CDXOrganizationalContact struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Phone string `json:"phone"`
}

type CDXProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

// TODO return pointer
func UnMarshalLicenseChoice(data interface{}) (CDXLicenseChoice, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)

	if errMarshal != nil {
		return CDXLicenseChoice{}, errMarshal
	}

	// optimistically, prepare the receiving structure
	// and unmarshal
	lc := CDXLicenseChoice{}
	errUnmarshal := json.Unmarshal(jsonString, &lc)

	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	//getLogger().Tracef("\n%s", getLogger().FormatStruct(lc))
	return lc, errUnmarshal
}

// TODO return pointer
func UnMarshalComponent(data interface{}) (CDXComponent, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// we need to marshal the data to normalize it to a []byte
	jsonString, errMarshal := json.Marshal(data)

	if errMarshal != nil {
		return CDXComponent{}, errMarshal
	}

	// optimistically, prepare the receiving structure
	// and unmarshal
	component := CDXComponent{}
	errUnmarshal := json.Unmarshal(jsonString, &component)

	if errUnmarshal != nil {
		getLogger().Warningf("unmarshal failed: %v", errUnmarshal)
	}

	//getLogger().Tracef("\n%s", getLogger().FormatStruct(component))

	return component, errUnmarshal
}
