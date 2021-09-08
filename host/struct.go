package host

import (
	"GoSyncDNS/Only"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

func SetHostName(fqdn string) *Hostname {
	var h Hostname
	h.Error = h.SetHostName(fqdn)
	return &h
}

type Host struct {
	HostName Hostname `json:"hostname"` // Host machine DNS name
	Port     int      `json:"port"`     // Service Port
	Text     string   `json:"text"`     // Service info served as a TXT record
	TTL      uint32   `json:"ttl"`      // TTL of the service record
	AddrIPv4 net.IP   `json:"-"`        // Host machine IPv4 address
	AddrIPv6 net.IP   `json:"-"`        // Host machine IPv6 address
	Instance string   `json:"name"`     // Instance name (e.g. "My web page")
	Service  string   `json:"type"`     // Service name (e.g. _http._tcp.)

	Mac net.HardwareAddr `json:"mac"`

	Error error
}
type Hosts []Host

func (d *Host) SetHostName(fqdn string) error {
	return d.HostName.SetHostName(fqdn)
}

func (d *Host) SetPort(port string) error {
	var err error

	for range Only.Once {
		if port == "" {
			break
		}

		d.Port, d.Error = strconv.Atoi(port)
		if d.Error != nil {
			break
		}
	}

	return err
}

func (d *Host) SetText(txt ...string) error {
	var err error

	for range Only.Once {
		if len(txt) == 0 {
			break
		}

		d.Text = strings.Join(txt, " ")
	}

	return err
}

func (d *Host) SetTtl(ttl string) error {
	var err error

	for range Only.Once {
		if ttl == "" {
			break
		}

		var t uint64
		t, d.Error = strconv.ParseUint(ttl, 10, 32)
		if d.Error != nil {
			break
		}
		d.TTL = uint32(t)
	}

	return err
}

func (d *Host) SetIpAddr(ip string) error {
	var err error

	for range Only.Once {
		if ip == "" {
			break
		}

		d.AddrIPv4 = net.ParseIP(ip)
	}

	return err
}

func (d *Host) SetIpv6Addr(ip string) error {
	var err error

	for range Only.Once {
		if ip == "" {
			break
		}

		d.AddrIPv6 = net.ParseIP(ip)
	}

	return err
}

func (d *Host) SetInstance(txt ...string) error {
	var err error

	for range Only.Once {
		if len(txt) == 0 {
			break
		}

		d.Instance = strings.Join(txt, " ")
	}

	return err
}

func (d *Host) SetService(txt ...string) error {
	var err error

	for range Only.Once {
		if len(txt) == 0 {
			break
		}

		d.Instance = strings.Join(txt, ".")
	}

	return err
}

func (d *Host) SetMac(mac string) error {
	var err error

	for range Only.Once {
		if mac == "" {
			break
		}

		d.Mac, d.Error = net.ParseMAC(mac)
	}

	return err
}

func (d *Host) ChangeDomain(domain string) error {
	return d.HostName.ChangeDomain(domain)
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
