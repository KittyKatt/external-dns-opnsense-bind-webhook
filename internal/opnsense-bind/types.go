package opnsense

// Config represents the configuration for the UniFi API.
type Config struct {
	Host          string `env:"OPNSENSE_HOST,notEmpty"`
	Key           string `env:"OPNSENSE_API_KEY,notEmpty"`
	Secret        string `env:"OPNSENSE_API_SECRET,notEmpty"`
	SkipTLSVerify bool   `env:"OPNSENSE_SKIP_TLS_VERIFY" envDefault:"true"`
	// TODO: Figure out automatic PTR creation
	// CreatePTRRecords bool   `env:"OPNSENSE_CREATE_PTR" envDefault:"false"`
}

// DNSDomain represents a DNS domain in BIND.
type DNSDomain struct {
	Id      string `json:"id"`
	Enabled string `json:"enabled"`
	Name    string `json:"name"`
	Type    string `json:"type"`
}

// DNSRecord represents a DNS record in BIND.
type DNSRecord struct {
	Id         string `json:"id"`
	Enabled    string `json:"enabled"`
	Name       string `json:"name"`
	Domain     string `json:"domain"`
	DomainUUID string `json:"domainUuid"`
	Type       string `json:"type"`
	Value      string `json:"value"`
}

type APINewDNSRecord struct {
	Record APINewDNSRecordInner `json:"record"`
}

// APINewDNSRecordInner represents the structure of an add_record request
// to the OPNSense BIND Plugin API.
type APINewDNSRecordInner struct {
	Name   string `json:"name"`
	Domain string `json:"domain"`
	Type   string `json:"type"`
	Value  string `json:"value"`
}

// APISelectOption represents a selectable option in an OPNSense API
// response.
type APISelectOption struct {
	Value    string `json:"value"`
	Selected int    `json:"selected"`
}

// SelectOption represents an object derived from an APISelectOption
type SelectOption struct {
	Id    string `json:"id"`
	Value string `json:"value"`
}

type APIRecordsRoot struct {
	Record APIRecordsOuter `json:"record"`
}
type APIRecordsOuter struct {
	Records APIRecords `json:"records"`
}

// APIRecords represents the API response for pulling records from the
// OPNSense BIND Plugin API.
type APIRecords struct {
	Record map[string]APIRecord `json:"record"`
}

// APIRecord represents a DNS record in the Opnsense BIND Plugin API.
type APIRecord struct {
	Enabled string                     `json:"enabled"`
	Domain  map[string]APISelectOption `json:"domain"`
	Name    string                     `json:"name"`
	Type    map[string]APISelectOption `json:"type"`
	Value   string                     `json:"value"`
}

type APIDomainsRoot struct {
	Domain APIDomainsOuter `json:"domain"`
}
type APIDomainsOuter struct {
	Domains APIDomains `json:"domains"`
}

// APIDomains represents the API response for pulling domains from the
// OPNSense BIND Plugin API.
type APIDomains struct {
	Domain map[string]APIDomain `json:"domain"`
}

// APIRecord represents a DNS domain in the Opnsense BIND Plugin API.
type APIDomain struct {
	Enabled string                     `json:"enabled"`
	Name    string                     `json:"domainname"`
	Type    map[string]APISelectOption `json:"type"`
}

// APIAddRecordResponse represents the structure of a response from the
// OPNSense BIND Plugin API when adding a record.
type APIAddRecordResponse struct {
	Result string `json:"result"`
	UUID   string `json:"uuid"`
}
