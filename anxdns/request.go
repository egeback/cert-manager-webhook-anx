package anxdns

const (
	GET    string = "GET"
	POST   string = "POST"
	PUT    string = "PUT"
	DELETE string = "DELETE"
)

type Request struct {
	QueryParams string ``
	Type        string
	JsonData    []byte
}
