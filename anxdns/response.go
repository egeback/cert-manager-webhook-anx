package anxdns

type Response struct {
	Status     string   `json:"status"`
	StatusCode int      `json:"statusCode"`
	ApiVersion string   `json:"apiVersion"`
	DnsRecords []Record `json:"dnsRecords"`
}
