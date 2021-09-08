package syncDns

import (
	"GoSyncDNS/Only"
	"github.com/miekg/dns"
	"net"
	"regexp"
)

//type Hostname struct {
//	Name string
//	Domain string
//	FQDN string
//}
//func (d *DNS) ParseHostname(fqdn string) Hostname {
//	var host Hostname
//
//	for range Only.Once {
//		if fqdn == "" {
//			break
//		}
//
//		host.Domain = d.Domain.FQDN
//		a := dns.SplitDomainName(fqdn)
//		//fmt.Printf("%s / %s\n", a[0], a[1])
//		switch len(a) {
//		case 1:
//			host.Name = a[0]
//		case 2:
//			host.Name = a[0]
//			host.Domain = a[1] + "."
//		}
//
//		host.FQDN = fmt.Sprintf("%s.%s", host.Name, host.Domain)
//	}
//
//	return host
//}

type RevHostname struct {
	Name string
	Zone string
}

func (d *DNS) ParseReverse(ip string) RevHostname {
	var host RevHostname

	for range Only.Once {
		if ip == "" {
			break
		}

		i := net.ParseIP(ip)
		host.Name, _ = dns.ReverseAddr(i.String())
		reg := regexp.MustCompile(`^\d+\.`)
		host.Zone = reg.ReplaceAllString(host.Name, "")

	}

	return host
}
