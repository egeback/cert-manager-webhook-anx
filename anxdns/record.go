package anxdns

type Record struct {
	// Cpanelresult  	string	`json:"cpanelresult"`
	Line   string `json:"line"`
	Record string `json:"record"`
	TTL    string `json:"ttl"`
	Type   string `json:"type"`
	// Raw				string	`json:"raw"`
	Name  string `json:"name"`
	Cname string `json:"cname"`
	//Exchange		string		`json:"exchange"`
	Address string `json:"address"`
	Txtdata string `json:"txtdata"`
	DynHost bool   `json:"dynhost"`
	Mname   string `json:"mname"`
}
