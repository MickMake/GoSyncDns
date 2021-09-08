package syncDns

import (
	"GoSyncDNS/Only"
	"GoSyncDNS/host"
	"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/miekg/dns"
	"net"
	"strings"
)

type DNS struct {
	ClientConfig *dns.ClientConfig
	Client       *dns.Client
	HostPort     string
	Domain       Domain
	Error        error
	Debug        bool

	debug bool
	msg   *dns.Msg
	key   *TSigOptions
	OutputType
}

type Domain struct {
	FQDN        string
	Nameservers []Nameserver
	DSSet       []DS
}

type Nameserver struct {
	Hostname string
	IPv4     net.IP
}

type DS struct {
	KeyTag     uint16
	Algorithm  uint8
	DigestType uint8
	Digest     string
}

type TSigOptions struct {
	Name      string
	Algorithm string
	Secret    string
}

const (
	TypeJson   = iota
	TypeHuman  = iota
	TypeGoogle = iota
)

type OutputType int

func New(server string, domain string) *DNS {
	var p DNS

	for range Only.Once {
		p.key = &TSigOptions{
			Name:      "rndc_key",
			Algorithm: "hmac-sha256",
			Secret:    "5zZLiasaXS1Hxrmr3POMzVYkDmgBvkbTIXFa/SJsQEY=",
		}
		p.OutputType = TypeHuman

		//p.ClientConfig, p.Error = dns.ClientConfigFromFile("/etc/resolv.conf")
		//if p.Error != nil {
		//	break
		//}

		p.ClientConfig = &dns.ClientConfig{
			Servers:  []string{server},
			Search:   []string{domain},
			Port:     "53",
			Ndots:    0,
			Timeout:  0,
			Attempts: 0,
		}

		server := Nameserver{
			Hostname: server,
			//IPv4:     net.IPv4(10, 0, 1, 52),
		}
		p.Domain = Domain{
			FQDN:        domain,
			Nameservers: []Nameserver{server},
			DSSet:       nil,
		}

		p.Client = new(dns.Client)
		p.Clear()
		p.HostPort = net.JoinHostPort(p.ClientConfig.Servers[0], p.ClientConfig.Port)
	}

	return &p
}

func (d *DNS) Clear() {
	d.msg = nil
	d.msg = new(dns.Msg)
}

func (d *DNS) Execute() error {

	for range Only.Once {
		//d.msg.RemoveRRset([]dns.RR{
		//	//&dns.NS{
		//	//	Hdr: dns.RR_Header{
		//	//		Name:   domain.FQDN,
		//	//		Rrtype: dns.TypeNS,
		//	//	},
		//	//	Ns: d.ClientConfig.Servers[0],
		//	//},
		//	&req2,
		//	//&dns.DS{
		//	//	Hdr: dns.RR_Header{
		//	//		Name:   domain.FQDN,
		//	//		Rrtype: dns.TypeDS,
		//	//	},
		//	//},
		//})
		//var newRRs []dns.RR
		//for _, ns := range domain.Nameservers {
		//	u := fmt.Sprintf("%s 172800 IN NS %s", domain.FQDN, ns.Hostname)
		//	rr, err := dns.NewRR(u)
		//	if err != nil {
		//		break
		//	}
		//
		//	newRRs = append(newRRs, rr)
		//
		//	if ns.IPv4 != nil {
		//		u = fmt.Sprintf("%s 172800 IN A %s", domain.FQDN, ns.IPv4.String())
		//		rr, err = dns.NewRR(u)
		//		if err != nil {
		//			break
		//		}
		//
		//		newRRs = append(newRRs, rr)
		//	}
		//}
		//
		//rr1, _ := dns.NewRR("42.1.0.10.in-addr.arpa.             IN PTR  zaphod.homenet.")
		//rr2, _ := dns.NewRR("zaphod.homenet.         IN A    10.0.1.42")
		//rr3, _ := dns.NewRR("")
		//d.msg.Insert([]dns.RR{rr2})
		if d.msg == nil {
			d.Error = errors.New("message is empty")
			break
		}

		if d.debug {
			fmt.Println("DNS update...")
			spew.Dump(d.msg)
		}

		d.msg, _, d.Error = d.Client.Exchange(d.msg, d.HostPort)
		if d.msg == nil {
			d.Error = errors.New(fmt.Sprintf("Error: %v\n", d.Error))
			break
		}

		if d.msg.Rcode != dns.RcodeSuccess {
			d.Error = errors.New(fmt.Sprintf("Failed with error code: %v\n", d.msg.Rcode))
			//foo := r.SetRcodeFormatError(r)
			//d.Error = errors.New(fmt.Sprintf("Failed with error code: %v\n", foo.Rcode))
			break
		}

		if d.Error != nil {
			break
		}
	}

	return d.Error
}

func (d *DNS) FindDomain(subnet string) string {
	var ret string

	for range Only.Once {
		rev := d.ParseReverse(subnet)

		d.Clear()

		d.msg.SetQuestion(rev.Zone, dns.TypeSOA)
		d.msg.RecursionDesired = true

		d.msg, _, d.Error = d.Client.Exchange(d.msg, d.HostPort)
		if d.msg == nil {
			d.Error = errors.New(fmt.Sprintf("*** error: %v\n", d.Error))
			break
		}

		if d.msg.Rcode != dns.RcodeSuccess {
			//d.Error = errors.New(fmt.Sprintf(" *** invalid answer name %s after MX query for %s\n", subnet))
			break
		}

		if d.Error != nil {
			break
		}

		if d.debug {
			fmt.Println("DNS answer...")
			spew.Dump(d.msg.Answer)
		}
		for _, a := range d.msg.Answer {
			if t, ok := a.(*dns.SOA); ok {
				hn := host.SetHostName(t.Ns)
				ret = hn.Domain
				//fmt.Printf("Domain: %s\n", ret)
			}
		}
	}

	return ret
}

func (d *DNS) SearchMx(name string) error {

	for range Only.Once {
		d.msg.SetQuestion(dns.Fqdn(name), dns.TypeMX)
		d.msg.RecursionDesired = true

		d.msg, _, d.Error = d.Client.Exchange(d.msg, d.HostPort)
		if d.msg == nil {
			d.Error = errors.New(fmt.Sprintf("*** error: %v\n", d.Error))
			break
		}

		if d.msg.Rcode != dns.RcodeSuccess {
			d.Error = errors.New(fmt.Sprintf(" *** invalid answer name %s after MX query for %s\n", name))
			break
		}

		if d.Error != nil {
			break
		}

		// Stuff must be in the answer section
		for _, a := range d.msg.Answer {
			fmt.Printf("%v\n", a)
		}
	}

	return d.Error
}

func (d *DNS) SyncToDomain(hosts ...host.Host) error {

	for range Only.Once {
		if len(hosts) == 0 {
			break
		}

		for _, h := range hosts {
			d.Clear()

			domain := d.FindDomain(h.AddrIPv4.String())
			if d.Debug {
				fmt.Printf("########################################\n")
				fmt.Printf("# Domain: %s\n", domain)
				fmt.Printf("########################################\n")
			}
			d.Error = h.ChangeDomain(domain)
			if d.Error != nil {
				break
			}

			d.Clear()
			d.Error = d.Del(h.TTL, h.HostName.FQDN, "")
			if d.Error != nil {
				break
			}

			d.Clear()
			d.Error = d.Add(h.TTL, h.HostName.FQDN, h.AddrIPv4.String())
			if d.Error != nil {
				break
			}

			if h.Mac.String() == "" {
				break
			}
			d.Clear()
			d.Error = d.AddTxt(h.TTL, h.HostName.FQDN,
				"mac:%s\nPort:%d\nTTL:%d\nservice:%s\ninstance:%s\nText:%s\n",
				h.Mac.String(),
				h.Port,
				h.TTL,
				h.Service,
				h.Instance,
				h.Text,
			)
			if d.Error != nil {
				break
			}
		}
	}

	return d.Error
}

func (d *DNS) AddTxt(ttl uint32, fqdn string, txt string, args ...interface{}) error {

	for range Only.Once {
		if ttl == 0 {
			ttl = 3600
		}
		if fqdn == "" {
			break
		}
		if txt == "" {
			break
		}
		txt = fmt.Sprintf(txt, args...)
		txtArray := strings.Split(txt, "\n")

		var h *host.Hostname
		h = host.SetHostName(fqdn)
		if h.Error != nil {
			d.Error = h.Error
			break
		}
		d.Domain.FQDN = h.Domain
		d.msg.SetUpdate(h.Domain)

		fmt.Printf("Adding TXT: %s\n%s\n", h.FQDN, txt)
		request := dns.TXT{
			Hdr: dns.RR_Header{
				Name:   h.FQDN,
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    ttl,
			},
			Txt: txtArray,
		}
		d.msg.Insert([]dns.RR{&request})

		d.Error = d.Execute()
		if d.Error != nil {
			break
		}
	}

	return d.Error
}

func (d *DNS) Add(ttl uint32, fqdn string, ip ...string) error {

	for range Only.Once {
		if fqdn == "" {
			break
		}
		if len(ip) == 0 {
			break
		}

		d.Error = d.AddForward(ttl, fqdn, ip...)
		if d.Error != nil {
			break
		}
		d.Error = d.Execute()
		if d.Error != nil {
			break
		}

		if len(ip) == 1 {
			d.Clear()
			d.Error = d.AddReverse(ttl, fqdn, ip[0])
			if d.Error != nil {
				break
			}
			d.Error = d.Execute()
			if d.Error != nil {
				break
			}
		}
	}

	return d.Error
}

func (d *DNS) AddForward(ttl uint32, fqdn string, ips ...string) error {

	for range Only.Once {
		if fqdn == "" {
			break
		}
		if len(ips) == 0 {
			break
		}

		var h *host.Hostname
		h = host.SetHostName(fqdn)
		if h.Error != nil {
			d.Error = h.Error
			break
		}
		d.Domain.FQDN = h.Domain
		d.msg.SetUpdate(h.Domain)

		for _, ip := range ips {
			i := net.ParseIP(ip)
			fmt.Printf("Adding forward: %s => %s\n", h.FQDN, i.String())

			request := dns.A{
				Hdr: dns.RR_Header{
					Name:   h.FQDN,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ttl, // 3600,
				},
				A: i,
			}
			d.msg.Insert([]dns.RR{&request})
		}

		//d.msg.RemoveRRset([]dns.RR{
		//	//&dns.NS{
		//	//	Hdr: dns.RR_Header{
		//	//		Name:   domain.FQDN,
		//	//		Rrtype: dns.TypeNS,
		//	//	},
		//	//	Ns: d.ClientConfig.Servers[0],
		//	//},
		//	&req2,
		//	//&dns.DS{
		//	//	Hdr: dns.RR_Header{
		//	//		Name:   domain.FQDN,
		//	//		Rrtype: dns.TypeDS,
		//	//	},
		//	//},
		//})
		//var newRRs []dns.RR
		//for _, ns := range domain.Nameservers {
		//	u := fmt.Sprintf("%s 172800 IN NS %s", domain.FQDN, ns.Hostname)
		//	rr, err := dns.NewRR(u)
		//	if err != nil {
		//		break
		//	}
		//
		//	newRRs = append(newRRs, rr)
		//
		//	if ns.IPv4 != nil {
		//		u = fmt.Sprintf("%s 172800 IN A %s", domain.FQDN, ns.IPv4.String())
		//		rr, err = dns.NewRR(u)
		//		if err != nil {
		//			break
		//		}
		//
		//		newRRs = append(newRRs, rr)
		//	}
		//}
		//
		//rr1, _ := dns.NewRR("42.1.0.10.in-addr.arpa.             IN PTR  zaphod.homenet.")
		//rr2, _ := dns.NewRR("zaphod.homenet.         IN A    10.0.1.42")
		//rr3, _ := dns.NewRR("")
		//d.msg.Insert([]dns.RR{rr2})
	}

	return d.Error
}

func (d *DNS) AddReverse(ttl uint32, fqdn string, ip string) error {

	for range Only.Once {
		if ip == "" {
			break
		}

		var h *host.Hostname
		h = host.SetHostName(fqdn)
		if h.Error != nil {
			d.Error = h.Error
			break
		}
		i := d.ParseReverse(ip)
		fmt.Printf("Adding reverse: %s\t%s => %s\n", i.Zone, i.Name, h.FQDN)

		d.msg.SetUpdate(i.Zone)

		request := dns.PTR{
			Hdr: dns.RR_Header{
				Name:     i.Name,
				Rrtype:   dns.TypePTR,
				Class:    dns.ClassINET,
				Ttl:      ttl,
				Rdlength: 0,
			},
			Ptr: h.FQDN,
		}
		d.msg.Insert([]dns.RR{&request})

		//fmt.Println(d.msg.String())
		//b := dns.CanonicalName(h)
		//fmt.Printf("dns.ReverseAddr: %s\n", b)
		//d.msg.RemoveRRset([]dns.RR{
		//	//&dns.NS{
		//	//	Hdr: dns.RR_Header{
		//	//		Name:   domain.FQDN,
		//	//		Rrtype: dns.TypeNS,
		//	//	},
		//	//	Ns: d.ClientConfig.Servers[0],
		//	//},
		//	&req2,
		//	//&dns.DS{
		//	//	Hdr: dns.RR_Header{
		//	//		Name:   domain.FQDN,
		//	//		Rrtype: dns.TypeDS,
		//	//	},
		//	//},
		//})
		//var newRRs []dns.RR
		//for _, ns := range domain.Nameservers {
		//	u := fmt.Sprintf("%s 172800 IN NS %s", domain.FQDN, ns.Hostname)
		//	rr, err := dns.NewRR(u)
		//	if err != nil {
		//		break
		//	}
		//
		//	newRRs = append(newRRs, rr)
		//
		//	if ns.IPv4 != nil {
		//		u = fmt.Sprintf("%s 172800 IN A %s", domain.FQDN, ns.IPv4.String())
		//		rr, err = dns.NewRR(u)
		//		if err != nil {
		//			break
		//		}
		//
		//		newRRs = append(newRRs, rr)
		//	}
		//}
		//
		//rr1, _ := dns.NewRR("42.1.0.10.in-addr.arpa.             IN PTR  zaphod.homenet.")
		//rr2, _ := dns.NewRR("zaphod.homenet.         IN A    10.0.1.42")
		//rr3, _ := dns.NewRR("")
		//d.msg.Insert([]dns.RR{rr2})
	}

	return d.Error
}

func (d *DNS) Del(ttl uint32, fqdn string, ip ...string) error {

	for range Only.Once {
		if ttl == 0 {
			ttl = 3600
		}
		if fqdn == "" {
			break
		}
		if len(ip) == 0 {
			break
		}

		d.Clear()
		d.Error = d.DelForward(ttl, fqdn, ip...)
		if d.Error != nil {
			break
		}
		d.Error = d.Execute()
		if d.Error != nil {
			break
		}

		if len(ip) == 1 {
			d.Clear()
			d.Error = d.DelReverse(ttl, fqdn, ip[0])
			if d.Error != nil {
				break
			}
			d.Error = d.Execute()
			if d.Error != nil {
				break
			}
		}
	}

	return d.Error
}

func (d *DNS) DelForward(ttl uint32, fqdn string, ips ...string) error {

	for range Only.Once {
		if fqdn == "" {
			break
		}
		if len(ips) == 0 {
			break
		}

		var h *host.Hostname
		h = host.SetHostName(fqdn)
		if h.Error != nil {
			d.Error = h.Error
			break
		}
		d.Domain.FQDN = h.Domain
		d.msg.SetUpdate(h.Domain)

		for _, ip := range ips {
			d.msg.SetUpdate(h.Domain)

			i := net.ParseIP(ip)
			fmt.Printf("Deleting forward: %s => %s\n", h.FQDN, i.String())

			request := dns.A{
				Hdr: dns.RR_Header{
					Name:   h.FQDN,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    ttl,
				},
				A: i,
			}
			d.msg.Remove([]dns.RR{&request})
		}

		//d.msg.RemoveName([]dns.RR{&request})
		//d.msg.RemoveRRset([]dns.RR{
		//	//&dns.NS{
		//	//	Hdr: dns.RR_Header{
		//	//		Name:   domain.FQDN,
		//	//		Rrtype: dns.TypeNS,
		//	//	},
		//	//	Ns: d.ClientConfig.Servers[0],
		//	//},
		//	&req2,
		//	//&dns.DS{
		//	//	Hdr: dns.RR_Header{
		//	//		Name:   domain.FQDN,
		//	//		Rrtype: dns.TypeDS,
		//	//	},
		//	//},
		//})
		//var newRRs []dns.RR
		//for _, ns := range domain.Nameservers {
		//	u := fmt.Sprintf("%s 172800 IN NS %s", domain.FQDN, ns.Hostname)
		//	rr, err := dns.NewRR(u)
		//	if err != nil {
		//		break
		//	}
		//
		//	newRRs = append(newRRs, rr)
		//
		//	if ns.IPv4 != nil {
		//		u = fmt.Sprintf("%s 172800 IN A %s", domain.FQDN, ns.IPv4.String())
		//		rr, err = dns.NewRR(u)
		//		if err != nil {
		//			break
		//		}
		//
		//		newRRs = append(newRRs, rr)
		//	}
		//}
		//
		//rr1, _ := dns.NewRR("42.1.0.10.in-addr.arpa.             IN PTR  zaphod.homenet.")
		//rr2, _ := dns.NewRR("zaphod.homenet.         IN A    10.0.1.42")
		//rr3, _ := dns.NewRR("")
		//d.msg.Insert([]dns.RR{rr2})
	}

	return d.Error
}

func (d *DNS) DelReverse(ttl uint32, fqdn string, ip string) error {

	for range Only.Once {
		if ip == "" {
			break
		}

		var h *host.Hostname
		h = host.SetHostName(fqdn)
		if h.Error != nil {
			d.Error = h.Error
			break
		}

		i := d.ParseReverse(ip)
		fmt.Printf("Deleting to zone: %s\t%s => %s\n", i.Zone, i.Name, h.FQDN)

		d.msg.SetUpdate(i.Zone)

		request := dns.PTR{
			Hdr: dns.RR_Header{
				Name:     i.Name,
				Rrtype:   dns.TypePTR,
				Class:    dns.ClassINET,
				Ttl:      ttl,
				Rdlength: 0,
			},
			Ptr: h.FQDN,
		}
		d.msg.Remove([]dns.RR{&request})

		//fmt.Println(d.msg.String())
		//b := dns.CanonicalName(h)
		//fmt.Printf("dns.ReverseAddr: %s\n", b)
		//d.msg.RemoveRRset([]dns.RR{
		//	//&dns.NS{
		//	//	Hdr: dns.RR_Header{
		//	//		Name:   domain.FQDN,
		//	//		Rrtype: dns.TypeNS,
		//	//	},
		//	//	Ns: d.ClientConfig.Servers[0],
		//	//},
		//	&req2,
		//	//&dns.DS{
		//	//	Hdr: dns.RR_Header{
		//	//		Name:   domain.FQDN,
		//	//		Rrtype: dns.TypeDS,
		//	//	},
		//	//},
		//})
		//var newRRs []dns.RR
		//for _, ns := range domain.Nameservers {
		//	u := fmt.Sprintf("%s 172800 IN NS %s", domain.FQDN, ns.Hostname)
		//	rr, err := dns.NewRR(u)
		//	if err != nil {
		//		break
		//	}
		//
		//	newRRs = append(newRRs, rr)
		//
		//	if ns.IPv4 != nil {
		//		u = fmt.Sprintf("%s 172800 IN A %s", domain.FQDN, ns.IPv4.String())
		//		rr, err = dns.NewRR(u)
		//		if err != nil {
		//			break
		//		}
		//
		//		newRRs = append(newRRs, rr)
		//	}
		//}
		//
		//rr1, _ := dns.NewRR("42.1.0.10.in-addr.arpa.             IN PTR  zaphod.homenet.")
		//rr2, _ := dns.NewRR("zaphod.homenet.         IN A    10.0.1.42")
		//rr3, _ := dns.NewRR("")
		//d.msg.Insert([]dns.RR{rr2})
	}

	return d.Error
}
