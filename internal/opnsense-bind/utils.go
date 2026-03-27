package opnsense

import (
	"strings"
)

// RecordFQDNSplitter splits a hostname into two parts,
// [0] Being the top level hostname
// [1] Being the subdomain/domain
//
// TODO: really this should return (hostname, domain string)
func SplitRecordFQDN(hostname string) []string {
	return strings.SplitN(hostname, ".", 2)
}

func JoinRecordFQDN(name string, zone string) string {
	return strings.Join([]string{name, zone}, ".")
}

func GetSelectedOption(selectMap map[string]APISelectOption) SelectOption {
	var selected SelectOption
	for objKey, obj := range selectMap {
		if obj.Selected == 1 {
			selected.Id = objKey
			selected.Value = obj.Value
		}
	}

	return selected
}
