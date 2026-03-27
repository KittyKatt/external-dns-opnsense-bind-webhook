package opnsense

import (
	"context"
	"fmt"

	log "github.com/sirupsen/logrus"
	"sigs.k8s.io/external-dns/endpoint"
	"sigs.k8s.io/external-dns/plan"
	"sigs.k8s.io/external-dns/provider"
)

// Provider type for interfacing with Opnsense
type Provider struct {
	provider.BaseProvider

	client       *httpClient
	domainFilter endpoint.DomainFilter
}

// NewOpnsenseProvider initializes a new DNSProvider.
func NewOpnsenseProvider(domainFilter endpoint.DomainFilter, config *Config) (provider.Provider, error) {
	c, err := newOpnsenseClient(config)

	if err != nil {
		return nil, fmt.Errorf("provider: failed to create the opnsense client: %w", err)
	}

	p := &Provider{
		client:       c,
		domainFilter: domainFilter,
	}

	return p, nil
}

// Records returns the list of records in Opnsense BIND Plugin.
func (p *Provider) Records(ctx context.Context) ([]*endpoint.Endpoint, error) {
	log.Debugf("records: retrieving records from opnsense")

	records, err := p.client.GetRecords()
	if err != nil {
		return nil, err
	}

	var endpoints []*endpoint.Endpoint
	for _, record := range records {
		if !p.domainFilter.MatchParent(record.Name) {
			continue
		}
		log.Debugf("record found (name: %s) (domain: %s) (type: %s) (value: %s)", record.Name, record.Domain, record.Type, record.Value)
		var targets endpoint.Targets

		targets = endpoint.NewTargets(record.Value)

		ep := &endpoint.Endpoint{
			DNSName:    JoinRecordFQDN(record.Name, record.Domain),
			RecordType: record.Type,
			Targets:    targets,
		}

		log.Debugf("endpoints: endpoint built: (name: %s)", ep.DNSName)

		endpoints = append(endpoints, ep)
	}

	return endpoints, nil
}

// ApplyChanges applies a given set of changes in the DNS provider.
func (p *Provider) ApplyChanges(ctx context.Context, changes *plan.Changes) error {
	for _, endpoint := range append(changes.UpdateOld, changes.Delete...) {
		log.Debugf("delete: endpoint name to delete: %s", endpoint.DNSName)
		if err := p.client.DeleteRecord(endpoint, p.domainFilter); err != nil {
			return err
		}
	}

	for _, endpoint := range append(changes.Create, changes.UpdateNew...) {
		log.Debugf("create: endpoint name to create: %s", endpoint.DNSName)
		if _, err := p.client.CreateRecord(endpoint, p.domainFilter); err != nil {
			return err
		}
	}

	p.client.ReconfigureBIND()

	return nil
}

// GetDomainFilter returns the domain filter for the provider.
func (p *Provider) GetDomainFilter() endpoint.DomainFilter {
	return p.domainFilter
}
