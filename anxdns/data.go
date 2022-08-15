package anxdns

type Data struct {
	Domain  string `json:"domain"`
	Type    string `json:"type"`
	Name    string `json:"name"`
	TTL     int    `json:"ttl"`
	Address string `json:"ttl,omitempty"`
	TxtData string `json:"ttl,omitempty"`
	Line    int    `json:"ttl,omitempty"`
}
