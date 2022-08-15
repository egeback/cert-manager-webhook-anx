package anxdns

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"strings"

	"k8s.io/klog/v2"
)

const (
	defaultTTL int = 3600
)

type AnxDnsClient struct {
	BaseURL string `https://dyn.anx.se/api/dns/`
	Domain  string
	ApiKey  string
}

func _communicate(client AnxDnsClient, apiRequest Request) []byte {
	// Create client
	httpClient := &http.Client{}

	var request *http.Request
	var error error

	if apiRequest.JsonData == nil {
		request, error = http.NewRequest(apiRequest.Type, client.BaseURL+apiRequest.QueryParams, nil)
	} else {
		request, error = http.NewRequest(apiRequest.Type, client.BaseURL+apiRequest.QueryParams, bytes.NewBuffer(apiRequest.JsonData))
	}

	if error != nil {
		fmt.Println(error)
	}

	request.Header.Add("Content-Type", "application/json")
	request.Header.Add("apikey", client.ApiKey)

	response, error := httpClient.Do(request)
	if error != nil {
		fmt.Println(error)
	}

	defer func() {
		err := response.Body.Close()
		if err != nil {
			klog.Fatal(err)
		}
	}()

	// Read response body
	respBody, _ := ioutil.ReadAll(response.Body)

	// Display results
	/// fmt.Println("response Status : ", response.Status)
	// fmt.Println("response Body : ", string(respBody))

	return respBody
}

func addTxtRecord(client AnxDnsClient, name string, txt string, ttl int) {
	record := Data{
		Domain:  client.Domain,
		Type:    "TXT",
		Name:    name,
		TTL:     ttl,
		TxtData: txt,
	}

	jsonData, _ := json.Marshal(record)

	apiRequest := Request{
		Type:     POST,
		JsonData: jsonData,
	}

	_communicate(client, apiRequest)
}

func addARecord(client AnxDnsClient, name string, address string, ttl int) {
	record := Data{
		Domain:  client.Domain,
		Type:    "A",
		Name:    name,
		TTL:     ttl,
		Address: address,
	}

	jsonData, _ := json.Marshal(record)

	apiRequest := Request{
		Type:     POST,
		JsonData: jsonData,
	}

	_communicate(client, apiRequest)
}

func addCNameRecord(client AnxDnsClient, name string, address string, ttl int) {
	record := Data{
		Domain:  client.Domain,
		Type:    "CNAME",
		Name:    name,
		TTL:     ttl,
		Address: address,
	}

	jsonData, _ := json.Marshal(record)

	apiRequest := Request{
		Type:     POST,
		JsonData: jsonData,
	}

	_communicate(client, apiRequest)
}

func verifyOrGetRecord(client AnxDnsClient, line int, name string, recordType string) Record {
	var record Record
	if line > 0 {
		record = getRecordsByLine(client, line)
	} else if len(name) > 0 {
		records := getRecordsByName(client, name)
		if len(records) == 0 {
			panic(errors.New("0 records with that name"))
		} else if len(records) > 1 {
			panic(errors.New(">1 record with that name. Specify line instead of name."))
		}
		record = records[0]
	} else {
		panic(errors.New("Line or name needs to be provided"))
	}

	if len(recordType) > 0 && record.Type != recordType {
		panic(errors.New("Record is not a " + recordType))
	}

	return record

}

func deleteRecordsByTxt(client AnxDnsClient, name string) {

}

func getAllRecords(client AnxDnsClient) []Record {
	request := Request{
		Type: GET,
	}
	respBody := _communicate(client, request)
	response := Response{}
	if err := json.Unmarshal(respBody, &response); err != nil {
		panic(err)
	}
	return response.DnsRecords
}

func getRecordsByName(client AnxDnsClient, name string) []Record {
	all_records := getAllRecords(client)

	return parseRecordsByName(all_records, name)
}

func getRecordsByLine(client AnxDnsClient, line int) Record {
	all_records := getAllRecords(client)

	return parseRecordsByLine(all_records, line)
}

func getRecordsByTxt(client AnxDnsClient, txt string, name string) []Record {
	var records []Record
	if name != "" {
		records = getRecordsByName(client, name)
	} else {
		records = getAllRecords(client)
	}

	return parseRecordsByTxt(records, txt)
}

func parseRecordsByTxt(all_records []Record, txt string) []Record {
	var records []Record

	for _, record := range all_records {
		if record.Type == "TXT" && record.Txtdata == txt {
			records = append(records, record)
		}
	}

	return records
}

func parseRecordsByName(all_records []Record, name string) []Record {
	n := name
	if !strings.HasSuffix(n, ".") {
		n = name + "."
	}

	var records []Record

	for _, record := range all_records {
		if record.Name == name {
			records = append(records, record)
		}
	}

	return records
}

func parseRecordsByLine(all_records []Record, line int) Record {
	var records []Record

	for _, record := range all_records {
		if record.Line == strconv.Itoa(line) {
			records = append(records, record)
		}
	}
	if len(records) > 0 {
		return records[0]
	}

	panic(errors.New("No records found"))
}
