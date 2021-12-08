package utils

import (
	"encoding/json"
	"fmt"

	"github.com/hokaccha/go-prettyjson"
)

func PrettyJSON(rawData interface{}) (string, error) {
	formatter := prettyjson.NewFormatter()
	bytes, err := formatter.Marshal(rawData)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}

func FormatStructAsJsonString(a interface{}) string {
	out, err := json.Marshal(a)
	if err == nil {
		return string(out)
	}
	return ""
}

func ConvertMapToJSONString(name string, mapIn interface{}) string {
	strMapOut, _ := json.MarshalIndent(mapIn, "", "  ")
	return fmt.Sprintf("%s: %s", name, string(strMapOut))
}

// TODO: function NOT complete, only placeholder type switch
func ConvertAnyToAny(values ...interface{}) {
	fmt.Printf("values=%v\n", values)
	for index, value := range values {
		fmt.Printf("value[%d] (%T): %+v\n", index, value, value)
		switch t := value.(type) {
		case int:
		case uint:
		case int32:
		case int64:
		case uint64:
			fmt.Println("Type is an integer:", t)
		case float32:
		case float64:
			fmt.Println("Type is a float:", t)
		case string:
			fmt.Println("Type is a string:", t)
		case nil:
			fmt.Println("Type is nil.")
		case bool:
			fmt.Println("Type is a bool:", t)
		default:
			fmt.Printf("Type is unknown!: %v\n", t)
		}
	}
}
