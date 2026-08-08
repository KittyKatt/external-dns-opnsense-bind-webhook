package opnsense

import (
	"context"
	"errors"
	"fmt"
	"strings"

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
		cleanName := strings.TrimSpace(record.Name)
		if cleanName == "" {
			cleanName = "@"
		}

		if !p.domainFilter.MatchParent(cleanName) {
			continue
		}
		log.Debugf("record found (name: %s) (domain: %s) (type: %s) (value: %s)", cleanName, record.Domain, record.Type, record.Value)
		var targets endpoint.Targets

		targets = endpoint.NewTargets(record.Value)

		var dnsName string
		if cleanName == "@" {
			dnsName = record.Domain
		} else {
			dnsName = JoinRecordFQDN(cleanName, record.Domain)
		}

		ep := &endpoint.Endpoint{
			DNSName:    dnsName,
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
	var errs []error
	changed := false

	// 1. Handle Deletions
	for _, endpoint := range append(changes.UpdateOld, changes.Delete...) {
		log.Debugf("delete: endpoint name to delete: %s", endpoint.DNSName)
		if err := p.client.DeleteRecord(endpoint, p.domainFilter); err != nil {
			log.Errorf("delete error for %s: %v", endpoint.DNSName, err)
			errs = append(errs, fmt.Errorf("delete %s: %w", endpoint.DNSName, err))
		} else {
			changed = true
		}
	}

	// 2. Handle Creations/Updates
	for _, endpoint := range append(changes.Create, changes.UpdateNew...) {
		log.Debugf("create: endpoint name to create: %s", endpoint.DNSName)
		if _, err := p.client.CreateRecord(endpoint, p.domainFilter); err != nil {
			if err == ErrNoChangeNeeded {
				continue
			}
			log.Errorf("create error for %s: %v", endpoint.DNSName, err)
			errs = append(errs, fmt.Errorf("create %s: %w", endpoint.DNSName, err))
		} else {
			changed = true
		}
	}

	// 3. Reconfigure BIND (Only if we didn't have massive failures, or always)
	if len(errs) == 0 && changed {
		if err := p.client.ReconfigureBIND(); err != nil {
			errs = append(errs, fmt.Errorf("reconfigure: %w", err))
		}
	} else {
		log.Debugf("skipping reconfigure because %d errors occurred", len(errs))
	}

	// 4. Return all errors at once
	if len(errs) > 0 {
		return fmt.Errorf("apply changes failed with %d errors: %v", len(errs), errors.Join(errs...))
	}

	return nil
}

// GetDomainFilter returns the domain filter for the provider.
func (p *Provider) GetDomainFilter() endpoint.DomainFilter {
	return p.domainFilter
}
