package utils

import (
	"encoding/json"
	"fmt"
)

// TODO: What is the value of this wrapper method over basic encoder?
func ConvertMapToJson(name string, mapIn interface{}) ([]byte, error) {
	strMapOut, err := json.MarshalIndent(mapIn, "", "  ")
	return strMapOut, err
}

// TODO: function NOT complete, only placeholder type switch
func ConvertAnyToAny(values ...interface{}) {
	//fmt.Printf("values=%v\n", values)
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
