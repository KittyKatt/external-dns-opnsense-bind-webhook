package opnsense

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"strings"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
)

const emptyJSONObject = "{}"

// httpClient is the DNS provider client.
type httpClient struct {
	*Config
	*http.Client
	baseURL *url.URL
}

// newOpnsenseClient creates a new DNS provider client.
func newOpnsenseClient(config *Config) (*httpClient, error) {
	u, err := url.Parse(config.Host)
	if err != nil {
		return nil, fmt.Errorf("parse url: %w", err)
	}

	// Ensure the base path is correctly set
	basePath, err := url.Parse("api/bind/")
	if err != nil {
		return nil, fmt.Errorf("parse base path: %w", err)
	}
	u = u.ResolveReference(basePath)

	// Create the HTTP client
	client := &httpClient{
		Config: config,
		Client: &http.Client{
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: config.SkipTLSVerify},
			},
		},
		baseURL: u,
	}

	if err := client.login(); err != nil {
		return nil, err
	}

	return client, nil
}

// login performs a basic call to validate credentials
func (c *httpClient) login() error {
	// Perform the test call by getting service status
	resp, err := c.doRequest(
		http.MethodGet,
		"service/status",
		nil,
	)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Check if the login was successful
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Errorf("login: failed: %s, response: %s", resp.Status, string(respBody))
		return fmt.Errorf("login: failed: %s", resp.Status)
	}
	return nil
}

// doRequest makes an HTTP request to the Opnsense firewall.
func (c *httpClient) doRequest(method, path string, body io.Reader) (*http.Response, error) {
	u := c.baseURL.ResolveReference(&url.URL{
		Path: path,
	})

	log.Debugf("doRequest: making %s request to %s", method, u)

	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}

	c.setHeaders(req)

	resp, err := c.Client.Do(req)
	if err != nil {
		return nil, err
	}

	log.Debugf("doRequest: response code from %s request to %s: %d", method, u, resp.StatusCode)

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		return nil, fmt.Errorf("doRequest: %s request to %s was not successful: %d", method, u, resp.StatusCode)
	}

	return resp, nil
}

// GetDoains retrieves the list of domains from the Opnsense Firewall's BIND plugin API.
func (c *httpClient) GetDomains() ([]DNSDomain, error) {
	resp, err := c.doRequest(
		http.MethodGet,
		"domain/get",
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiDomains APIDomainsRoot
	if err = json.NewDecoder(resp.Body).Decode(&apiDomains); err != nil {
		return nil, err
	}

	domains := make([]DNSDomain, 0, len(apiDomains.Domain.Domains.Domain))
	for domainUUID, domain := range apiDomains.Domain.Domains.Domain {
		log.Debugf("lookupDomain: Found domain: (name: %s) (id: %s) (type: %s) (enabled: %s)", domain.Name, domainUUID, domain.Type, domain.Enabled)
		domainType := GetSelectedOption(domain.Type)

		dnsDomain := DNSDomain{
			Id:      domainUUID,
			Enabled: domain.Enabled,
			Name:    domain.Name,
			Type:    domainType.Value,
		}

		domains = append(domains, dnsDomain)
	}

	if domains == nil {
		return []DNSDomain{}, nil
	} else {
		return domains, nil
	}
}

// GetRecords retrieves the list of records from the Opnsense Firewall's BIND plugin API.
// These are equivalent to A, AAAA, CNAME, TXT records
func (c *httpClient) GetRecords() ([]DNSRecord, error) {
	resp, err := c.doRequest(
		http.MethodGet,
		"record/get",
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var apiRecords APIRecordsRoot
	if err = json.NewDecoder(resp.Body).Decode(&apiRecords); err != nil {
		return nil, err
	}

	records := make([]DNSRecord, 0, len(apiRecords.Record.Records.Record))
	for recordUUID, record := range apiRecords.Record.Records.Record {
		domain := GetSelectedOption(record.Domain)
		recordType := GetSelectedOption(record.Type)

		var recordValue string
		// normalize CNAME values
		if recordType.Value == "CNAME" {
			recordValue = strings.TrimSuffix(record.Value, ".")
		} else {
			recordValue = record.Value
		}

		if recordValue == domain.Value {
			recordValue = "@"
		}

		dnsRecord := DNSRecord{
			Id:         recordUUID,
			Enabled:    record.Enabled,
			Name:       record.Name,
			Domain:     domain.Value,
			DomainUUID: domain.Id,
			Type:       recordType.Value,
			Value:      recordValue,
		}

		records = append(records, dnsRecord)
	}

	if records == nil {
		return []DNSRecord{}, nil
	} else {
		return records, nil
	}
}

// CreateRecord creates a new DNS A, AAAA, CNAME, TXT record in the Opnsense Firewall's BIND Plugin API.
func (c *httpClient) CreateRecord(endpoint *endpoint.Endpoint, domainFilter endpoint.DomainFilter) (*DNSRecord, error) {
	log.Debugf("create: Try pulling pre-existing BIND %s record: %s", endpoint.RecordType, endpoint.DNSName)
	lookup, err := c.lookupRecord(endpoint.DNSName, endpoint.RecordType, domainFilter)
	if err != nil {
		return nil, err
	}

	if lookup != nil {
		log.Debugf("create: Found uuid: %s", lookup.Id)
		log.Debugf("create: Found existing %s record for %s : %s", endpoint.RecordType, endpoint.DNSName, lookup.Id)
		return lookup, nil
	}

	domain, err := c.lookupDomain(endpoint.DNSName, domainFilter)
	if err != nil {
		return nil, err
	}

	// Add trailing dot to CNAME records
	var endpointTarget string
	var recordName string
	if endpoint.RecordType == "CNAME" {
		endpointTarget = endpoint.Targets[0] + "."
		if endpoint.DNSName == domain.Name {
			recordName = "@"
		} else {
			recordName = strings.TrimSuffix(endpoint.DNSName, domain.Name)
		}
	} else if endpoint.RecordType == "TXT" {
		endpointTarget = endpoint.Targets[0]

		recordName = strings.TrimSuffix(endpoint.DNSName, domain.Name)
	} else {
		endpointTarget = endpoint.Targets[0]
		recordName = strings.TrimSuffix(endpoint.DNSName, domain.Name)
	}

	recordName = strings.TrimSuffix(recordName, ".")

	record := APINewDNSRecord{
		Record: APINewDNSRecordInner{
			Type:   endpoint.RecordType,
			Name:   recordName,
			Domain: domain.Id,
			Value:  endpointTarget,
		},
	}

	jsonBody, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}

	log.Debugf("create: POST: %s", string(jsonBody))
	resp, err := c.doRequest(
		http.MethodPost,
		"record/add_record",
		bytes.NewReader(jsonBody),
	)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// TODO: Better error handling if API returns:
	// {"result":"failed"}
	//if resp.Body != nil && resp.Body

	var respRecord APIAddRecordResponse
	if err = json.NewDecoder(resp.Body).Decode(&respRecord); err != nil {
		return nil, err
	}

	log.Debugf("create: created record: %+v", respRecord)

	return nil, nil
}

// DeleteRecord deletes a DNS record from the Opnsense Firewall's BIND Plugin API.
func (c *httpClient) DeleteRecord(endpoint *endpoint.Endpoint, domainFilter endpoint.DomainFilter) error {
	log.Debugf("delete: Deleting record %+v", endpoint)
	lookup, err := c.lookupRecord(endpoint.DNSName, endpoint.RecordType, domainFilter)
	if err != nil {
		return err
	}

	log.Debugf("delete: Found match %s", lookup.Id)

	log.Debugf("delete: Sending POST %s", lookup.Id)
	resp, err := c.doRequest(
		http.MethodPost,
		path.Join("record/del_record", lookup.Id),
		strings.NewReader(emptyJSONObject),
	)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	return nil
}

// lookupDomain finds a Domain in the Opnsense Firewall's BIND Plugin API.
func (c *httpClient) lookupDomain(key string, domainFilter endpoint.DomainFilter) (*DNSDomain, error) {
	domains, err := c.GetDomains()
	if err != nil {
		return nil, err
	}

	if key == "" {
		log.Debug("a domain cannot be empty")
		return nil, fmt.Errorf("a domain cannot be empty")
	}

	if len(key) > 253 {
		log.Debugf("invalid domain, length exceeds 253 characters: %s", key)
		return nil, fmt.Errorf("invalid domain, length exceeds 253 characters")
	}

	dnsName := strings.TrimSpace(strings.ToLower(key))
	hostParts := strings.Split(dnsName, ".")

	if len(hostParts) == 1 {
		log.Errorf("dns name is TLD or invalid format: %s", dnsName)
		return nil, fmt.Errorf("dns name is TLD or invalid format: %s", dnsName)
	}

	var domainName string
	var domain DNSDomain
	longestSuffix := ""
	for i := 0; i < len(hostParts); i++ {
		domainName := strings.Join(hostParts[i:], ".")
		log.Debugf("lookupDomain: Looking for domain matching string: %s", domainName)
	for _, d := range domains {
			log.Debugf("lookupDomain: Checking Domain: Name=%s, Type=%s, ID=%s", d.Name, d.Type, d.Id)
			if len(d.Name) > len(longestSuffix) && domainName == d.Name {
				log.Debugf("lookupDomain: Match Found!  %s", d.Id)
			longestSuffix = d.Name
			domain = d
			}
		}
		if longestSuffix != "" {
			break
		}
	}

	if longestSuffix != "" {
		return &domain, nil
	}

	log.Debugf("lookup: No matching domain found for Name=%s", domainName)
	return nil, nil
}

// lookupRecord finds a HostOverride in the Opnsense Firewall's BIND Plugin API.
func (c *httpClient) lookupRecord(key, recordType string, domainFilter endpoint.DomainFilter) (*DNSRecord, error) {
	log.Debugf("lookup: debug: incoming key: %s", key)
	records, err := c.GetRecords()
	if err != nil {
		return nil, err
	}
	domain, err := c.lookupDomain(key, domainFilter)
	if err != nil {
		return nil, err
	}

	log.Debug("lookup: Splitting FQDN")
	hostName := strings.TrimSuffix(key, domain.Name)

	for _, r := range records {
		log.Debugf("lookup: Checking record: Host=%s, Domain=%s, Type=%s, ID=%s", r.Name, r.Domain, r.Type, r.Id)
		if r.Name == "@" && r.Domain == key && r.Type == recordType {
			log.Debugf("lookup: found root level UUID match: %s", r.Id)
			return &r, nil
		} else if r.Name == hostName && r.Domain == domain.Name && r.Type == recordType {
			log.Debugf("lookup: UUID Match Found: %s", r.Id)
			return &r, nil
		}
	}
	log.Debugf("lookup: No matching record found for Host=%s, Domain=%s, Type=%s", hostName, domain.Name, recordType)
	return nil, nil
}

// ReconfigureBIND performs a reconfigure action in BIND after editing records
func (c *httpClient) ReconfigureBIND() error {
	// Perform the reconfigure
	resp, err := c.doRequest(
		http.MethodPost,
		"service/reconfigure",
		strings.NewReader(emptyJSONObject),
	)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	// Check if the login was successful
	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		log.Errorf("reconfigure: login failed: %s, response: %s", resp.Status, string(respBody))
		return fmt.Errorf("reconfigure: BIND failed: %s", resp.Status)
	}

	return nil
}

// setHeaders sets the headers for the HTTP request.
func (c *httpClient) setHeaders(req *http.Request) {
	// Add basic auth header
	opnsenseAuth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", c.Config.Key, c.Config.Secret)))
	req.Header.Add("Authorization", fmt.Sprintf("Basic %s", opnsenseAuth))
	req.Header.Add("Accept", "application/json")
	if req.Method != http.MethodGet {
		req.Header.Add("Content-Type", "application/json; charset=utf-8")
	}
	// Log the request URL
	log.Debugf("headers: Requesting %s", req.URL)
}
