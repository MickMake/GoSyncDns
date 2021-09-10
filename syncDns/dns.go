package syncDns

import (
	"GoSyncDNS/Only"
	"GoSyncDNS/host"
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"net"
	"strings"
)

type DNS struct {
	ClientConfig *dns.ClientConfig
	Client       *dns.Client
	HostPort     string
	Domain       Domain
	MirrorDomain string
	Error        error

	bufferSize uint16
	debug      bool
	msg        *dns.Msg
	key        *TSigOptions
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

func New(debug bool, server string, domain string, mirror string) *DNS {
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
			Timeout:  30,
			Attempts: 8,
		}

		server := Nameserver{
			Hostname: server,
			IPv4:     net.ParseIP(server),
		}
		p.Domain = Domain{
			FQDN:        domain,
			Nameservers: []Nameserver{server},
			DSSet:       nil,
		}

		p.Client = new(dns.Client)
		p.Clear()
		p.HostPort = net.JoinHostPort(p.ClientConfig.Servers[0], p.ClientConfig.Port)

		p.MirrorDomain = mirror
		p.debug = debug
		p.bufferSize = DefaultBufferSize
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
			//fmt.Println("DNS query...")
			//fmt.Printf("%v", d.msg)
		}

		if d.bufferSize == 0 {
			d.bufferSize = DefaultBufferSize
		}

		d.msg.SetEdns0(d.bufferSize, true)
		d.msg, _, d.Error = d.Client.Exchange(d.msg, d.HostPort)
		if d.msg == nil {
			d.Error = errors.New(fmt.Sprintf("Error: %v\n", d.Error))
			break
		}

		if d.debug {
			//fmt.Println("DNS answer...")
			//fmt.Printf("%v", d.msg.Answer)
		}

		if d.msg.Rcode != dns.RcodeSuccess {
			d.Error = errors.New(fmt.Sprintf("Failed with error code: %v\n%v\n", d.msg.Rcode, d.msg))
			//foo := r.SetRcodeFormatError(r)
			//d.Error = errors.New(fmt.Sprintf("Failed with error code: %v\n", foo.Rcode))
			break
		}

		if d.Error != nil {
			d.Error = errors.New(fmt.Sprintf("Error: %v\n%v\n", d.Error, d.msg))
			break
		}
	}

	//fmt.Printf("MESSAGE:\n%v\n", d.msg)
	return d.Error
}

func (d *DNS) FindDomain(subnet string) string {
	var ret string

	for range Only.Once {
		rev := host.New()

		d.Error = rev.ParseReverse(subnet)
		if d.Error != nil {
			break
		}

		d.Clear()
		d.msg.SetQuestion(rev.GetReverseZone(), dns.TypeSOA)
		d.msg.RecursionDesired = true

		d.Error = d.Execute()
		if d.Error != nil {
			break
		}

		for _, a := range d.msg.Answer {
			if t, ok := a.(*dns.SOA); ok {
				hn := host.SetHostName(t.Ns)
				ret = hn.Domain
				//fmt.Printf("Domain: %s\n", ret)
				break
			}
		}
	}

	return ret
}

// List: Similar to dig @10.0.5.12 -tAXFR +all domain
func (d *DNS) List(zone string) error {

	for range Only.Once {
		if zone == "" {
			zone = d.Domain.FQDN
		}
		d.msg.SetQuestion(dns.Fqdn(zone), dns.TypeAXFR)
		d.msg.RecursionDesired = true

		//d.HostPort = "tcp:" + strings.TrimPrefix(d.HostPort, "udp:")
		d.Client.Net = "tcp"
		d.Error = d.Execute()
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

func (d *DNS) Query(n string, t string) *host.Host {
	h := host.New()

	for range Only.Once {
		d.Clear()

		if n == "" {
			h.Error = errors.New("empty host / IP")
			break
		}

		h.Error = h.Set(n)
		if h.Error != nil {
			break
		}

		name := h.GetFQDN()
		zone := h.GetForwardZone()
		h.SetForward()
		if zone == "" {
			name = h.GetReverse()
			zone = h.GetReverseZone()
			h.SetReverse()
		}
		name = dns.Fqdn(name)
		d.msg.SetQuestion(name, d.lookupType(t))

		//fmt.Printf("%v", d.msg)
		h.Error = d.Execute()
		//fmt.Printf("%v", d.msg)
		if h.Error != nil {
			break
		}

		//var rev string
		for _, a := range d.msg.Answer {
			//fmt.Printf("%v\n", a)
			h.Records = append(h.Records, a.String())

			if t, ok := a.(*dns.A); ok {
				// fmt.Printf("A: %s\n", t)
				_ = h.SetIpAddr(t.A.String())
				_ = h.SetHostName(t.Hdr.Name)
				_ = h.SetLowerTtl(t.Hdr.Ttl)
				//rev = h.GetIpAddr().String()
				continue
			}

			if _, ok := a.(*dns.CNAME); ok {
				// fmt.Printf("CNAME: %s\n", t)
				continue
			}

			if _, ok := a.(*dns.MX); ok {
				// fmt.Printf("MX: %s\n", t)
				continue
			}

			if t, ok := a.(*dns.TXT); ok {
				// fmt.Printf("TXT: %s\n", t)
				_ = h.AppendText(t.Txt...)
				_ = h.SetHostName(t.Hdr.Name)
				_ = h.SetLowerTtl(t.Hdr.Ttl)
				continue
			}

			if _, ok := a.(*dns.NS); ok {
				// fmt.Printf("NS: %s\n", t)
				continue
			}

			if t, ok := a.(*dns.SOA); ok {
				// fmt.Printf("SOA: %s\n", t)
				//_ = h.SetText(t.String())
				_ = h.SetHostName(t.Hdr.Name)
				_ = h.SetLowerTtl(t.Hdr.Ttl)
				continue
			}

			//@TODO - Consider supporting SRV records.
			//https://www.cloudflare.com/en-gb/learning/dns/dns-records/dns-srv-record/
			if _, ok := a.(*dns.SRV); ok {
				// fmt.Printf("SRV: %s\n", t)
				continue
			}

			if t, ok := a.(*dns.PTR); ok {
				// fmt.Printf("PTR: %s\n", t)
				//_ = h.SetText(t.Ptr)
				if h.IsForward() {
					_ = h.SetHostName(t.Hdr.Name)
				} else {
					_ = h.SetHostName(t.Ptr)
				}
				_ = h.SetLowerTtl(t.Hdr.Ttl)
				continue
			}

			// fmt.Printf("%v\n", a)
		}

		//if rev != "" {
		//	// If we have an IP address, then lookup reverse zone.
		//	d.Clear()
		//	h2 := d.Query(rev, t)
		//	h.Error = h.Merge(h2)
		//}
	}

	return h
}

func (d *DNS) lookupType(lookup string) uint16 {
	var ret uint16

	switch strings.ToLower(lookup) {
	case "any":
		ret = dns.TypeANY
	case "a":
		ret = dns.TypeA
	case "cname":
		ret = dns.TypeCNAME
	case "mx":
		ret = dns.TypeMX
	case "txt":
		ret = dns.TypeTXT
	case "ns":
		ret = dns.TypeNS
	case "soa":
		ret = dns.TypeSOA
	case "srv":
		ret = dns.TypeSRV
	case "ptr":
		ret = dns.TypePTR
	default:
		ret = dns.TypeANY
	}

	return ret
}

func (d *DNS) SearchMx(name string) error {

	for range Only.Once {
		d.Clear()

		d.msg.SetQuestion(dns.Fqdn(name), dns.TypeMX)
		d.msg.RecursionDesired = true

		d.Error = d.Execute()
		if d.Error != nil {
			break
		}
		//d.msg, _, d.Error = d.Client.Exchange(d.msg, d.HostPort)
		//if d.msg == nil {
		//	d.Error = errors.New(fmt.Sprintf("error: %v\n", d.Error))
		//	break
		//}
		//
		//if d.msg.Rcode != dns.RcodeSuccess {
		//	d.Error = errors.New(fmt.Sprintf("error code: %d\n", d.msg.Rcode))
		//	break
		//}
		//
		//if d.Error != nil {
		//	break
		//}

		// Stuff must be in the answer section
		for _, a := range d.msg.Answer {
			fmt.Printf("%v\n", a)
		}
	}

	return d.Error
}

func (d *DNS) SyncHosts(hosts ...host.Host) error {

	for range Only.Once {
		d.Error = nil

		if len(hosts) == 0 {
			break
		}

		for _, h := range hosts {
			d.Clear()
			domain := d.FindDomain(h.GetIpAddr().String())
			if d.debug {
				fmt.Printf("########################################\n")
				fmt.Printf("# Host: %v", h)
				fmt.Printf("# Domain: %s\n", domain)
				fmt.Printf("########################################\n")
			}

			d.Error = d.SyncHost(domain, &h)
			if d.Error != nil {
				continue
			}

			if d.MirrorDomain == "" {
				continue
			}

			d.Error = d.SyncHost(d.MirrorDomain, &h)
			if d.Error != nil {
				continue
			}
		}
	}

	return d.Error
}

func (d *DNS) SyncHost(domain string, h *host.Host) error {

	for range Only.Once {
		d.Error = nil

		d.Clear()
		d.Error = h.ChangeDomain(domain)
		if d.Error != nil {
			break
		}

		// @TODO - Handle the delete better.
		// @TODO - TTL should resolve most of the timeouts, but we can't always be sure BIND does this.
		d.Clear()
		d.Error = d.DelForward(h)
		if d.Error != nil {
			break
		}
		d.Error = d.Execute()

		d.Clear()
		d.Error = d.DelReverse(h)
		if d.Error != nil {
			break
		}
		d.Error = d.Execute()

		d.Clear()
		d.Error = d.AddForward(h)
		if d.Error != nil {
			break
		}
		d.Error = d.Execute()

		d.Clear()
		d.Error = d.AddReverse(h)
		if d.Error != nil {
			break
		}
		d.Error = d.Execute()

		txt := fmt.Sprintf("%s", strings.ReplaceAll(h.GetText(), " ", "\n"))
		if h.Mac.String() != "" {
			txt = fmt.Sprintf("Mac:%s\nPort:%d\nTTL:%d\nService:%s\nInstance:%s\nText:%s\n",
				h.Mac.String(),
				h.Port,
				h.TTL,
				h.Service,
				h.Instance,
				h.Text)
		}

		d.Clear()
		d.Error = d.AddTxt(h, txt)
		if d.Error != nil {
			break
		}

		d.Error = d.Execute()
	}

	if d.Error != nil {
		fmt.Printf("Sync error: %s\n", d.Error)
	}

	return d.Error
}

func (d *DNS) AddTxt(h *host.Host, txt string, args ...interface{}) error {

	for range Only.Once {
		d.Error = nil

		if txt == "" {
			break
		}
		txt = fmt.Sprintf(txt, args...)
		txtArray := strings.Split(txt, "\n")

		d.Domain.FQDN = h.GetDomain()
		d.msg.SetUpdate(d.Domain.FQDN)

		request := dns.TXT{
			Hdr: dns.RR_Header{
				Name:   h.GetFQDN(),
				Rrtype: dns.TypeTXT,
				Class:  dns.ClassINET,
				Ttl:    h.GetTtl(),
			},
			Txt: txtArray,
		}

		fmt.Printf("Adding TXT zone(%s): %s => %s\n", h.GetDomain(), h.GetFQDN(), txt)
		d.msg.Insert([]dns.RR{&request})
	}

	return d.Error
}

func (d *DNS) Add(ttl string, fqdn string, ip string) error {

	for range Only.Once {
		h := d.toHostStruct(ttl, fqdn, ip)
		if h.Error != nil {
			d.Error = h.Error
			continue
		}

		d.Error = d.AddForward(h)
		if d.Error != nil {
			break
		}
		d.Error = d.Execute()
		if d.Error != nil {
			break
		}

		d.Clear()
		d.Error = d.AddReverse(h)
		if d.Error != nil {
			break
		}
		d.Error = d.Execute()
		if d.Error != nil {
			break
		}
	}

	return d.Error
}

func (d *DNS) AddForward(h *host.Host) error {

	for range Only.Once {
		d.Error = h.IsValid()
		if d.Error != nil {
			break
		}

		d.Domain.FQDN = h.GetDomain()
		d.msg.SetUpdate(d.Domain.FQDN)

		request := dns.A{
			Hdr: dns.RR_Header{
				Name:   h.GetFQDN(),
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    h.GetTtl(), // 3600,
			},
			A: h.GetIpAddr(),
		}

		fmt.Printf("Adding forward zone(%s): %s => %s\n", h.GetDomain(), h.GetFQDN(), h.GetIpAddr())
		d.msg.Insert([]dns.RR{&request})

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

func (d *DNS) AddReverse(h *host.Host) error {

	for range Only.Once {
		d.Error = h.IsValid()
		if d.Error != nil {
			break
		}

		d.msg.SetUpdate(h.GetReverseZone())
		request := dns.PTR{
			Hdr: dns.RR_Header{
				Name:     h.GetName(),
				Rrtype:   dns.TypePTR,
				Class:    dns.ClassINET,
				Ttl:      h.GetTtl(),
				Rdlength: 0,
			},
			Ptr: h.GetFQDN(),
		}

		fmt.Printf("Adding reverse zone(%s): %s => %s\n", h.GetReverseZone(), h.GetName(), h.GetFQDN())
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

func (d *DNS) DeleteAll(n string) error {

	for range Only.Once {
		h := d.Query(n, "ANY")
		if h.Error != nil {
			d.Error = h.Error
			break
		}

		//name := h.GetFQDN()
		//zone := h.GetForwardZone()
		//if zone == "" {
		//	name = h.GetReverse()
		//	zone = h.GetReverseZone()
		//}

		if h.GetForwardZone() != "" {
			d.Clear()
			d.Domain.FQDN = h.GetForwardZone()
			d.msg.SetUpdate(h.GetForwardZone())
			request := dns.ANY{
				Hdr: dns.RR_Header{
					Name:   h.GetFQDN(),
					Rrtype: dns.TypeANY,
					Class:  dns.ClassINET,
					Ttl:    h.GetTtl(),
				},
			}
			fmt.Printf("Deleting host zone(%s): %s\n", h.GetDomain(), h.GetFQDN())
			d.msg.RemoveName([]dns.RR{&request})
			//d.Error = d.Execute()
			h = d.Query(h.GetIpAddr().String(), "ANY")
		}

		if h.GetReverseZone() != "" {
			d.Clear()
			d.Domain.FQDN = h.GetReverseZone()
			d.msg.SetUpdate(h.GetReverseZone())
			request := dns.ANY{
				Hdr: dns.RR_Header{
					Name:   h.GetReverse(),
					Rrtype: dns.TypeANY,
					Class:  dns.ClassINET,
					Ttl:    h.GetTtl(),
				},
			}
			fmt.Printf("Deleting host zone(%s): %s\n", h.GetDomain(), h.GetFQDN())
			d.msg.RemoveName([]dns.RR{&request})
			//d.Error = d.Execute()
		}
	}

	return d.Error
}

func (d *DNS) Del(ttl string, fqdn string, ip string) error {

	for range Only.Once {
		h := d.toHostStruct(ttl, fqdn, ip)
		if h.Error != nil {
			d.Error = h.Error
			continue
		}

		d.Clear()
		d.Error = d.DelForward(h)
		if d.Error != nil {
			break
		}
		d.Error = d.Execute()
		// @TODO - Better delete handling.
		if d.Error != nil {
			break
		}

		d.Clear()
		d.Error = d.DelReverse(h)
		if d.Error != nil {
			break
		}
		d.Error = d.Execute()
		if d.Error != nil {
			break
		}
	}

	return d.Error
}

func (d *DNS) DelForward(h *host.Host) error {

	for range Only.Once {
		d.Error = h.IsValid()
		if d.Error != nil {
			break
		}

		d.Domain.FQDN = h.GetDomain()
		d.msg.SetUpdate(d.Domain.FQDN)

		request := dns.A{
			Hdr: dns.RR_Header{
				Name:   h.GetFQDN(),
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    h.GetTtl(),
			},
			A: h.GetIpAddr(),
		}

		fmt.Printf("Deleting forward: %s => %s\n", h.GetFQDN(), h.GetIpAddr())
		d.msg.Remove([]dns.RR{&request})
	}

	return d.Error
}

func (d *DNS) DelReverse(h *host.Host) error {

	for range Only.Once {
		d.Error = h.IsValid()
		if d.Error != nil {
			break
		}

		d.Domain.FQDN = h.GetDomain()
		d.msg.SetUpdate(h.GetReverseZone())

		request := dns.PTR{
			Hdr: dns.RR_Header{
				Name:     h.GetReverse(),
				Rrtype:   dns.TypePTR,
				Class:    dns.ClassINET,
				Ttl:      h.GetTtl(),
				Rdlength: 0,
			},
			Ptr: h.GetFQDN(),
		}

		fmt.Printf("Deleting in zone: %s\t%s => %s\n", h.GetReverseZone(), h.GetName(), h.GetFQDN())
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

//func (d *DNS) DelForward(h *host.Host) error {
//
//	for range Only.Once {
//		d.Error = h.IsValid()
//		if d.Error != nil {
//			break
//		}
//
//		d.Domain.FQDN = h.GetDomain()
//		d.msg.SetUpdate(d.Domain.FQDN)
//
//		for _, ip := range ips {
//			if ip == "" {
//				continue
//			}
//
//			d.Error = h.SetIpAddr(ip)
//			if d.Error != nil {
//				continue
//			}
//
//			request := dns.A{
//				Hdr: dns.RR_Header{
//					Name:   h.GetFQDN(),
//					Rrtype: dns.TypeA,
//					Class:  dns.ClassINET,
//					Ttl:    h.GetTtl(),
//				},
//				A: h.GetIpAddr(),
//			}
//
//			fmt.Printf("Deleting forward: %s => %s\n", h.GetFQDN(), h.GetIpAddr())
//			d.msg.Remove([]dns.RR{&request})
//		}
//
//		//d.msg.RemoveName([]dns.RR{&request})
//		//d.msg.RemoveRRset([]dns.RR{
//		//	//&dns.NS{
//		//	//	Hdr: dns.RR_Header{
//		//	//		Name:   domain.FQDN,
//		//	//		Rrtype: dns.TypeNS,
//		//	//	},
//		//	//	Ns: d.ClientConfig.Servers[0],
//		//	//},
//		//	&req2,
//		//	//&dns.DS{
//		//	//	Hdr: dns.RR_Header{
//		//	//		Name:   domain.FQDN,
//		//	//		Rrtype: dns.TypeDS,
//		//	//	},
//		//	//},
//		//})
//		//var newRRs []dns.RR
//		//for _, ns := range domain.Nameservers {
//		//	u := fmt.Sprintf("%s 172800 IN NS %s", domain.FQDN, ns.Hostname)
//		//	rr, err := dns.NewRR(u)
//		//	if err != nil {
//		//		break
//		//	}
//		//
//		//	newRRs = append(newRRs, rr)
//		//
//		//	if ns.IPv4 != nil {
//		//		u = fmt.Sprintf("%s 172800 IN A %s", domain.FQDN, ns.IPv4.String())
//		//		rr, err = dns.NewRR(u)
//		//		if err != nil {
//		//			break
//		//		}
//		//
//		//		newRRs = append(newRRs, rr)
//		//	}
//		//}
//		//
//		//rr1, _ := dns.NewRR("42.1.0.10.in-addr.arpa.             IN PTR  zaphod.homenet.")
//		//rr2, _ := dns.NewRR("zaphod.homenet.         IN A    10.0.1.42")
//		//rr3, _ := dns.NewRR("")
//		//d.msg.Insert([]dns.RR{rr2})
//	}
//
//	return d.Error
//}
