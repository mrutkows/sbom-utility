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

package log

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"

	"github.com/hokaccha/go-prettyjson"
)

func FormatMap(mapName string, field map[string]interface{}) (string, error) {

	var sb strings.Builder

	if reflect.ValueOf(field).Kind() != reflect.Map {
		return "", fmt.Errorf("invalid `Map`; actual Type: (%v)", reflect.TypeOf(field))
	}

	// m is a map[string]interface.
	// loop over keys and values in the map.
	for k, v := range field {
		sb.WriteString(fmt.Sprintf("[%s]: %+v", k, v))
	}

	return sb.String(), nil
}

func FormatStruct(structName string, field interface{}) (string, error) {

	if reflect.ValueOf(field).Kind() != reflect.Struct {
		return "", fmt.Errorf("invalid `Struct`; actual Type: (%v)", reflect.TypeOf(field))
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("  %s (%s) = {\n", structName, reflect.TypeOf(field)))

	structNames := reflect.TypeOf(field)
	numNames := structNames.NumField()

	// TODO: optionally, colorize keys/values; see "github.com/fatih/color" package
	// e.g., keys=white, string=green, floats/ints=cyan, bool=yellow, nil=magenta
	if numNames > 0 {
		flagValues := reflect.ValueOf(field)
		var name string
		var value interface{}
		var fieldType string

		for i := 0; i < numNames; i++ {
			name = structNames.Field(i).Name
			// TODO: using the .String() method interace reduces `[]byte` values
			// to "<[]uint8 Value>"; if you remove it, you see ALL the bytes
			// A better solution might be to show the first 'x' bytes (slice/truncate)
			value = flagValues.Field(i).String()

			//fmt.Printf("%t\n", reflect.Type.Field(i))

			// reflect.ValueOf(flagValues.Field(i)).Kind() == reflect.Array

			fieldType = fmt.Sprintf("(%+v)", flagValues.Field(i).Type())
			line := fmt.Sprintf("\t%12s %-10s %s %v\n", name, fieldType, ":", value)
			sb.WriteString(line)
		}
	} else {
		sb.WriteString("\t<empty>\n")
	}
	sb.WriteString("  }\n")

	return sb.String(), nil
}

// Output: {"ID":1,"Name":"Reds","Colors":["Crimson","Red","Ruby","Maroon"]}
// TODO: make variadic (for optional indent param) and call "Marshal" or "MarshalIndent"
func FormatInterfaceAsJson(a interface{}) string {
	out, err := json.Marshal(a)
	if err == nil {
		return string(out)
	}
	return ""
}

// Note: "go-prettyjson" colorizes output for shell output
func FormatInterfaceAsPrettyJson(rawData interface{}) (string, error) {
	formatter := prettyjson.NewFormatter()
	bytes, err := formatter.Marshal(rawData)
	if err != nil {
		return fmt.Sprintf("unable to marshal data of type (%T)", rawData), err
	}
	return string(bytes), nil
}
