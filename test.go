package main

import (
    "encoding/json"
    "fmt"
)
 	

func main() {

	domain := "egeback.se" 	
	label := "internal.egeback.se"
	txtdata := "testar"

	data := map[string]interface{}{
		"domain": domain,
		"type": "TXT",
		"name": label,
		"ttl": 3600,
		"txtdata": txtdata,
		"address": "",
	}

	var jsonData = []byte(`{
		"domain": domain,
		"type": "TXT",
		"name": label,
		"ttl": 3600,
		"txtdata": txtdata,
		"address": "",
	}`)

	strData, _ := json.Marshal(data)
	fmt.Println(string(strData))
	fmt.Println(string(jsonData))
}