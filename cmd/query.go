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
	"strings"

	"github.com/mrutkows/sbom-utility/utils"
	"github.com/spf13/cobra"
)

// Query command flags
const (
	FLAG_OUTPUT_FORMAT  = "format"
	FLAG_QUERY_SELECT   = "select"
	FLAG_QUERY_FROM     = "from"
	FLAG_QUERY_WHERE    = "where"
	FLAG_QUERY_ORDER_BY = "orderby"
)

// Query command flag help messages
const (
	FLAG_OUTPUT_FORMAT_HELP  = "Format output using the specific type. Valid values: \"json\""
	FLAG_QUERY_SELECT_HELP   = "comma-separated list of JSON keynames used to select fields within the object designated by the FROM flag."
	FLAG_QUERY_FROM_HELP     = "dot-separated list of JSON keynames used to dereference into the JSON document."
	FLAG_QUERY_WHERE_HELP    = "TODO"
	FLAG_QUERY_ORDER_BY_HELP = "TODO"
)

// Valid `--format` formats
const (
	FLAG_VALUE_OUTPUT_JSON = "json"
)

// Query error types
const (
	MSG_INVALID_JSON_MAP              = "invalid JSON map"
	MSG_INVALID_QUERY_REQUEST         = "invalid query request"
	MSG_INVALID_QUERY_RESPONSE        = "invalid query response"
	MSG_INVALID_QUERY_REQUEST_OBJ     = "invalid query request object"
	MSG_INVALID_QUERY_RESPONSE_OBJ    = "invalid query response object"
	MSG_QUERY_INVALID_SELECT_CLAUSE   = "invalid SELECT clause"
	MSG_QUERY_INVALID_FROM_CLAUSE     = "invalid FROM clause"
	MSG_QUERY_INVALID_WHERE_CLAUSE    = "invalid WHERE clause"
	MSG_QUERY_INVALID_ORDER_BY_CLAUSE = "invalid ORDERBY clause"
	MSG_QUERY_MISSING_FROM_SELECTORS  = "missing `--from` selectors"
)

// Query error details
const (
	MSG_ERROR_FROM_KEY_NOT_FOUND      = "key not found in path"
	MSG_ERROR_FROM_KEY_INVALID_OBJECT = "key does not reference a valid JSON object"
	MSG_ERROR_SELECT_WILDARD          = "wildcard cannot be used with other values"
)

// query JSON map and return selected subset
// SELECT
//    <key.1>, <key.2>, ... // "firstname, lastname, email" || * (default)
// FROM
//    <key path>            // "product.customers"
// WHERE
//    <key.X> == <value>    // "country='Germany'"
// ORDER BY
//    <key.N>               // "lastname"
//
// e.g.,SELECT * FROM product.customers WHERE country="Germany";
// TODO: design abbreviated WHERE syntax for command line
// TODO: design abbreviated ORDERBY syntax for command line
type QueryRequest struct {
	selectFieldsRaw     string
	selectFields        []string
	fromObjectsRaw      string
	fromObjectSelectors []string
	whereValuesRaw      string // TODO
	orderByKeysRaw      string // TODO
	//orderByKeys         []string // TODO
}

// Implement the Stringer interface for QueryRequest
func (qr *QueryRequest) String() string {
	sb := new(strings.Builder)
	sb.WriteString(fmt.Sprintf("--select: %s\n", qr.selectFieldsRaw))
	sb.WriteString(fmt.Sprintf("--from: %s\n", qr.fromObjectsRaw))
	sb.WriteString(fmt.Sprintf("--where: %s\n", qr.whereValuesRaw))
	sb.WriteString(fmt.Sprintf("--orderby: %s\n", qr.orderByKeysRaw))
	return sb.String()
}

type QueryResponse struct {
	resultMap map[string]interface{}
}

func NewQueryResponse() *QueryResponse {
	qr := new(QueryResponse)
	qr.resultMap = make(map[string]interface{})
	return qr
}

func NewCommandQuery() *cobra.Command {
	var command = new(cobra.Command)
	command.Use = "query --from \"\" -i <path/input-sbom.json>"
	command.Short = "query objects and values from SBOM (JSON) document"
	command.Long = "query objects and values from SBOM (JSON) document. Where <path> can be absolute or relative.The --from` is a dot-separated string of keys used to dereference into the JSON document."
	command.RunE = queryCmdImpl
	initCommandQuery(command)
	return command
}

func initCommandQuery(command *cobra.Command) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Add local flags to command
	command.PersistentFlags().StringVar(&utils.Flags.OutputFormat, FLAG_OUTPUT_FORMAT, FLAG_VALUE_OUTPUT_JSON, FLAG_OUTPUT_FORMAT_HELP)
	command.Flags().StringP(FLAG_QUERY_SELECT, "", "*", FLAG_QUERY_SELECT_HELP)
	command.Flags().StringP(FLAG_QUERY_FROM, "", "", FLAG_QUERY_FROM_HELP)
	command.Flags().StringP(FLAG_QUERY_WHERE, "", "", FLAG_QUERY_WHERE_HELP)
}

func (qr *QueryRequest) readQueryFlags(cmd *cobra.Command) error {
	getLogger().Enter()
	defer getLogger().Exit()

	var errGetString error

	// Read '--from` flag first as its result is required for any other field to operate on
	qr.fromObjectsRaw, errGetString = cmd.Flags().GetString(FLAG_QUERY_FROM)
	if errGetString != nil {
		return errGetString
	} else {
		getLogger().Tracef("Query: '%s' flag found: %s", FLAG_QUERY_FROM, qr.fromObjectsRaw)
	}

	// Read '--select' flag second as it is the next highly likely field (used to
	// reduce the result set from querying the "FROM" JSON object)
	qr.selectFieldsRaw, errGetString = cmd.Flags().GetString(FLAG_QUERY_SELECT)
	if errGetString != nil {
		getLogger().Tracef("Query: '%s' flag NOT found", FLAG_QUERY_SELECT)
	} else {
		getLogger().Tracef("Query: '%s' flag found: %s", FLAG_QUERY_SELECT, qr.selectFieldsRaw)
	}

	// Read '--where' flag second as it is the next likely field
	// (used to further reduce the set of results from field value "matches"
	// as part of the SELECT processing)
	qr.whereValuesRaw, errGetString = cmd.Flags().GetString(FLAG_QUERY_WHERE)
	if errGetString != nil {
		getLogger().Tracef("Query: '%s' flag NOT found", FLAG_QUERY_WHERE)
	} else {
		getLogger().Tracef("Query: '%s' flag found: %s", FLAG_QUERY_WHERE, qr.whereValuesRaw)
	}

	// Read '--orderby' flag to be used to order by field (keys) data in the "output" phase
	qr.orderByKeysRaw, errGetString = cmd.Flags().GetString(FLAG_QUERY_ORDER_BY)
	if errGetString != nil {
		getLogger().Tracef("Query: '%s' flag NOT found", FLAG_QUERY_ORDER_BY)
	} else {
		getLogger().Tracef("Query: '%s' flag found: %s", FLAG_QUERY_ORDER_BY, qr.orderByKeysRaw)
	}

	return nil
}

func (qr *QueryRequest) parseQueryClauses() {
	getLogger().Enter()
	defer getLogger().Exit()

	// parse out path (selectors) to JSON object from raw '--from' flag's value
	qr.fromObjectSelectors = strings.Split(qr.fromObjectsRaw, ".")
	getLogger().Tracef("FROM json object (path): %v\n", qr.fromObjectSelectors)

	// parse out field (keys) from raw '--select' flag's value
	qr.selectFields = strings.Split(qr.selectFieldsRaw, ",")
	getLogger().Tracef("SELECT keys (fields): %v\n", qr.selectFields)

	// TODO: need a simple logical syntax for WHERE clause
	// envision allowing only basic string match (with wildcard, perhaps regex)
	// Also, need to allow for "null" and "empty" logical comparisons

	// parse out field (keys) from raw '--select' flag's value
	qr.selectFields = strings.Split(qr.selectFieldsRaw, ",")
	getLogger().Tracef("SELECT keys (fields): %v\n", qr.selectFields)
}

func queryCmdImpl(cmd *cobra.Command, args []string) error {
	getLogger().Enter()

	// Note: returns error if either file load or unmarshal to JSON map fails
	document, errLoad := LoadInputFileAndUnmarshal()

	if errLoad != nil {
		getLogger().Error(errLoad)
		getLogger().Exit(errLoad)
		return errLoad
	}

	// Load/validate the query syntax
	var queryRequest *QueryRequest = new(QueryRequest)

	// Parse flags for query parameters
	errParseParams := queryRequest.readQueryFlags(cmd)
	queryRequest.parseQueryClauses()

	if errParseParams != nil {
		getLogger().Exit(errParseParams)
		return errParseParams
	}

	// allocate the result structure
	var queryResult *QueryResponse = new(QueryResponse)

	result, errQuery := query(document.GetMap(), queryRequest, queryResult)

	if errQuery != nil {
		getLogger().Exit(errQuery)
		return errQuery
	}

	// TODO: we default to "json" output format, but should be able to supply via flag
	// we would need solid use cases to support other formats...
	fResult, _ := utils.ConvertMapToJson("", result)

	// Always, output the (JSON) fromatted data directly to stdout;
	// This output is NOT subject to log-level settings
	fmt.Printf("%s\n", fResult)

	getLogger().Exit(result)
	return nil
}

// query JSON map and return selected subset
// i.e., use QueryRequest (syntax) to implement the query into the JSON document
func query(JsonMap map[string]interface{}, request *QueryRequest, response *QueryResponse) (interface{}, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	// Assure we have a map to dereference
	if JsonMap == nil {
		return nil, fmt.Errorf(MSG_INVALID_JSON_MAP)
	}

	if request == nil {
		return nil, fmt.Errorf(MSG_INVALID_QUERY_REQUEST_OBJ)
	}

	if response == nil {
		return nil, fmt.Errorf(MSG_INVALID_QUERY_RESPONSE_OBJ)
	}

	// allocate locals to hold results of "find" operation
	// initialize pointer to root of document
	var dataptr interface{} = JsonMap
	var errFind error

	// Note: this function will only use the "parsed" request data
	// and NOT use the "raw" data passed from a command line impl.
	// if a FROM select object is not provided, assume "root" search
	if len(request.fromObjectSelectors) == 0 ||
		request.fromObjectSelectors[0] == "" {
		getLogger().Tracef("request object FROM selectors empty; assume query uses document \"root\".")
	} else {
		// locate the JSON object we will select from
		dataptr, errFind = findFromObject(request, JsonMap)
	}

	// If we fail to find the object at the specified FROM path
	if errFind != nil {
		return nil, errFind
	}

	// assure that the return is indeed a JSON object (i.e., map[string]interface{})
	findObject, ok := dataptr.(map[string]interface{})
	if ok {
		// TODO: return this (map) output instead of the one from the "find" stage
		selected, errSelect := selectFields(request, findObject)

		if errSelect != nil {
			return nil, errSelect
		}

		// return selected "map" as interface{}
		dataptr = selected

	} else {
		getLogger().Warningf("the path declared on the '--from` flag (%s) does not dereference to a JSON object (%T).", request.fromObjectsRaw, dataptr)
	}
	return dataptr, nil
}

// Wrapper for base query function that returns a JSON map type
func queryMap(JsonMap map[string]interface{}, request *QueryRequest, response *QueryResponse) (map[string]interface{}, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	iResult, err := query(JsonMap, request, response)

	if err != nil {
		getLogger().Error(err)
		return nil, err
	}

	// retrieve the components array from the map
	mapResult, ok := iResult.(map[string]interface{})

	if !ok {
		return nil, getLogger().Errorf("invalid type found by query; expected `%s`, but found : `%T`", "map[string]infterface{}", iResult)
	}

	return mapResult, nil
}

// NOTE: it is the caller's responsibility to convert to other output formats
// based upon other flag values
func selectFields(request *QueryRequest, jsonMap map[string]interface{}) (map[string]interface{}, error) {

	// Default to wildcard behavior
	// TODO: init "from" selector to '*' (maybe)
	if len(request.selectFields) == 0 {
		return jsonMap, nil
	}

	// Check for wildcard; if it is the only selector, return
	if len(request.selectFields) == 1 {
		if request.selectFields[0] == "*" {
			return jsonMap, nil
		}
	}

	// allocate select map
	selectedOutput := make(map[string]interface{})

	// copy selected fields into output map
	for _, fieldKey := range request.selectFields {

		// validate wildcard not used with other fields; if so, that is a conflict
		if fieldKey == "*" {
			errSelectorsWithWildcard := getLogger().Errorf(": %s: %s ", MSG_QUERY_INVALID_SELECT_CLAUSE, MSG_ERROR_SELECT_WILDARD)
			return nil, errSelectorsWithWildcard
		}

		selectedOutput[fieldKey] = jsonMap[fieldKey]
	}

	return selectedOutput, nil
}

func findFromObject(request *QueryRequest, jsonMap map[string]interface{}) (interface{}, error) {
	getLogger().Enter()
	defer getLogger().Exit()

	var tempMap map[string]interface{} = jsonMap
	var dataptr interface{}

	getLogger().Tracef("Finding JSON object using path key(s): %v\n", request.fromObjectSelectors)

	for i, key := range request.fromObjectSelectors {
		dataptr = tempMap[key]

		// if we find a nil value, this means we failed to find the object
		if dataptr == nil {
			errPath := getLogger().Errorf(": %s: %s: %s", MSG_QUERY_INVALID_FROM_CLAUSE, MSG_ERROR_FROM_KEY_NOT_FOUND, key)
			return nil, errPath
		}

		// If the resulting value is indeed another map type, we expect for a Json Map
		// we preserve that pointer for the next iteration
		_, isMap := dataptr.(map[string]interface{})
		if isMap {
			tempMap = dataptr.(map[string]interface{})
		} else {

			// TODO: We only support an array (i.e., []interface{}) as the last selector
			// in theory, we could support arrays (perhaps array notation) in the FROM clause
			// at any point (e.g., "metadata.component.properties[0]").
			// we should still be able to support implicit arrays as well.
			_, isArray := dataptr.([]interface{})

			if isArray && ((i + 1) == len(request.fromObjectSelectors)) {
				getLogger().Errorf("%s: %s: %v (%T)", "FROM clause dereferences to an array", "value (type): ", dataptr, dataptr)
			} else {
				errPathObj := getLogger().Errorf(": %s: %s: %v (%T)", MSG_QUERY_INVALID_FROM_CLAUSE, MSG_ERROR_FROM_KEY_INVALID_OBJECT, dataptr, dataptr)
				return nil, errPathObj
			}
		}
	}
	return dataptr, nil
}
