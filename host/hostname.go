package host

import (
	"GoSyncDNS/Only"
	"errors"
	"fmt"
	"net"
	"strings"
)

func SetHostName(fqdn string) *Hostname {
	var h Hostname
	h.Error = h.SetHostName(fqdn)
	return &h
}

type Hostnames []*Hostname

func (h *Hostnames) HostExists(fqdn string, ip string) bool {
	var ok bool
	for range Only.Once {
		if ip == "" {
			ip = "<nil>"
		}
		src := fmt.Sprintf("%s/%s", fqdn, ip)
		for _, hn := range *h {
			cmp4 := fmt.Sprintf("%s/%s", hn.FQDN, hn.Address.AddrIPv4.String())
			if cmp4 == src {
				ok = true
				break
			}

			cmp6 := fmt.Sprintf("%s/%s", hn.FQDN, hn.Address.AddrIPv6.String())
			if cmp6 == src {
				ok = true
				break
			}
		}
	}
	return ok
}
func cmpStrings(src string, dst string) bool {
	var ok bool
	for range Only.Once {
		if src == "" {
			break
		}

		if dst == "" {
			break
		}

		if src != dst {
			break
		}
		ok = true
	}
	return ok
}

func (h *Hostnames) Last() *Hostname {
	if len(*h) == 0 {
		return nil
	}
	return (*h)[len(*h)-1]
}

//func (h *Hostnames) ChangeDomain(domain string) error {
//	return (*h)[len(*h)-1].ChangeDomain(domain)
//}
//
//func (h *Hostnames) GetName() string {
//	return (*h)[len(*h)-1].GetName()
//}
//
//func (h *Hostnames) GetDomain() string {
//	return (*h)[len(*h)-1].GetDomain()
//}
//
//func (h *Hostnames) GetFQDN() string {
//	return (*h)[len(*h)-1].GetFQDN()
//}
//
//func (h *Hostnames) GetReverseZone() string {
//	return (*h)[len(*h)-1].Address.ReverseZone
//}
//
//func (h *Hostnames) GetForwardZone() string {
//	return (*h)[len(*h)-1].Address.ForwardZone
//}
//
//func (h *Hostnames) GetReverse() string {
//	return (*h)[len(*h)-1].Address.Reverse
//}

type Hostname struct {
	Name    string
	Domain  string
	FQDN    string
	Address Address

	Record Record
	Error  error
}

func (h *Hostname) IsValid() error {
	for range Only.Once {
		if h.Name == "" {
			h.Error = errors.New("empty host name")
			break
		}

		if h.Domain == "" {
			h.Error = errors.New("empty domain name")
			break
		}

		if h.FQDN == "" {
			h.Error = errors.New("empty FQDN")
			break
		}

		if (h.Address.AddrIPv4.String() == "") && (h.Address.AddrIPv6.String() == "") {
			h.Error = errors.New("empty IP address")
			break
		}

		//if h.HostNames.Address.ForwardZone == "" {
		//	h.Error = errors.New("empty forward zone")
		//	break
		//}
		//
		//if h.HostNames.Address.ReverseZone == "" {
		//	h.Error = errors.New("empty reverse zone")
		//	break
		//}
	}
	return h.Error
}

func (h *Hostname) SetHostName(fqdn string) error {
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
			h.Name = a[0]
			h.Domain = "local."
		default:
			h.Name = a[0]
			h.Domain = strings.Join(a[1:], ".") + "."
			h.Address.ForwardZone = h.Domain
		}

		h.FQDN = fmt.Sprintf("%s.%s", h.Name, h.Domain)
	}

	return err
}

func (h *Hostname) SetRecord(t string, txt string) error {

	for range Only.Once {
		h.Record.Type = t
		h.Record.String = txt
	}

	return h.Error
}

//func (h *Hostname) AppendRecords(txt ...string) error {
//
//	for range Only.Once {
//		h.Record = append(h.Records, txt...)
//	}
//
//	return h.Error
//}

func (h *Hostname) ChangeDomain(domain string) error {
	var err error

	for range Only.Once {
		if domain == "" {
			break
		}
		h.Domain = strings.TrimSuffix(domain, ".") + "."
		h.FQDN = fmt.Sprintf("%s.%s", h.Name, h.Domain)
		h.Address.ForwardZone = h.Domain
	}

	return err
}

func ChangeDomain(name string, domain string) string {
	var ret string

	for range Only.Once {
		if name == "" {
			break
		}
		domain = strings.TrimSuffix(domain, ".") + "."

		ret = strings.TrimSuffix(name, ".") + "."
		n := SplitDomainName(ret)
		if len(n) == 0 {
			ret = name
			break
		}

		ret = fmt.Sprintf("%s.%s", n[0], domain)
	}

	return ret
}

func (h *Hostname) GetName() string {
	return h.Name
}

func (h *Hostname) GetFQDN() string {
	return h.FQDN
}

func (h *Hostname) GetDomain() string {
	return h.Domain
}

func (h *Hostname) GetReverseZone() string {
	return h.Address.ReverseZone
}

func (h *Hostname) GetForwardZone() string {
	return h.Address.ForwardZone
}

func (h *Hostname) GetReverse() string {
	return h.Address.Reverse
}

func (h *Hostname) GetIpAddr() net.IP {
	return h.Address.AddrIPv4
}

func (h *Hostname) SetIpAddr(ip string) error {
	return h.Address.SetIpAddr(ip)
}

func (h *Hostname) SetIpv6Addr(ip string) error {
	return h.Address.SetIpv6Addr(ip)
}

func (h *Hostname) ParseReverse(ip string) error {
	return h.Address.ParseReverse(ip)
}

func (h *Hostname) ParseSubnet(ip string) error {
	return h.Address.ParseSubnet(ip)
}

//func (h *Hostname) SetReverseZone(rev string) error {
//	return h.Address.SetReverseZone(rev)
//}

func (h *Hostname) String() string {
	var ret string

	ret += "\n########"
	ret += fmt.Sprintf("\n# FQDN: %s", h.FQDN)
	ret += fmt.Sprintf("\n# Hostname: %s", h.Name)
	ret += fmt.Sprintf("\n# Domain: %s", h.Domain)

	ret += fmt.Sprintf("\n# Address:\n\t%s", h.Address.String())
	ret += fmt.Sprintf("\n# Record: [%s] - %s", h.Record.Type, h.Record.String)

	return ret
}
