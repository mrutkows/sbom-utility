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

	"github.com/mrutkows/sbom-utility/schema"
	"github.com/mrutkows/sbom-utility/utils"
)

func LoadInputFileAndUnmarshal() (*schema.Sbom, error) {
	getLogger().Enter()
	getLogger().Trace(fmt.Sprintf("utils.Flags.InputFile: `%s`", utils.Flags.InputFile))

	// check for required fields on command
	if utils.Flags.InputFile == "" {
		return nil, fmt.Errorf("invalid input file (-%s): `%s` ", FLAG_FILENAME_INPUT_SHORT, utils.Flags.InputFile)
	}

	document := schema.NewSbom(utils.Flags.InputFile)

	getLogger().Info(fmt.Sprintf("Unmarshalling file `%s`...", utils.Flags.InputFile))

	// Load the raw, candidate SBOM (file) as JSON data
	// TODO: return error from unmarshal and stop further processing and exit
	errUnmarshal := document.UnmarshalSBOM() // i.e., utils.Flags.InputFile

	if errUnmarshal != nil {
		return document, errUnmarshal
	}

	getLogger().Exit()
	return document, nil
}
