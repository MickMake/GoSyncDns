package host

import (
	"GoSyncDNS/Only"
	"errors"
	"fmt"
	"strings"
)

func SetHostName(fqdn string) *Hostname {
	var h Hostname
	h.Error = h.SetHostName(fqdn)
	return &h
}

type Hostname struct {
	Name   string
	Domain string
	FQDN   string

	Error error
}

func (d *Hostname) SetHostName(fqdn string) error {
	var err error

	for range Only.Once {
		if fqdn == "" {
			err = errors.New("empty hostname")
			break
		}

		a := SplitDomainName(fqdn)
		//fmt.Printf("%s / %s\n", a[0], a[1])
		switch len(a) {
		case 0:
			err = errors.New("empty hostname")
		case 1:
			d.Name = a[0]
			d.Domain = "local."
		default:
			d.Name = a[0]
			d.Domain = strings.Join(a[1:], ".") + "."
		}

		d.FQDN = fmt.Sprintf("%s.%s", d.Name, d.Domain)
	}

	return err
}

func (d *Hostname) ChangeDomain(domain string) error {
	var err error

	for range Only.Once {
		if domain == "" {
			break
		}
		d.Domain = strings.TrimSuffix(domain, ".") + "."
		d.FQDN = fmt.Sprintf("%s.%s", d.Name, d.Domain)
	}

	return err
}

func (d *Hostname) GetName() string {
	return d.Name
}

func (d *Hostname) GetFQDN() string {
	return d.FQDN
}

func (d *Hostname) GetDomain() string {
	return d.Domain
}

func (d *Hostname) String() string {
	ret := fmt.Sprintf("\n# FQDN: %s\n# Hostname: %s\n# Domain: %s",
		d.FQDN,
		d.Name,
		d.Domain,
	)
	return ret
}
