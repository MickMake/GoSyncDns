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

		//fmt.Printf("Updating DNS...\n")
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

		d.Error = rev.LastHostname().ParseReverse(subnet)
		if d.Error != nil {
			break
		}

		d.Clear()
		d.msg.SetQuestion(rev.LastHostname().GetReverseZone(), dns.TypeSOA)
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

		hn := h.LastHostname()
		name := hn.GetFQDN()
		zone := hn.GetForwardZone()
		h.SetForward()
		if zone == "" {
			name = hn.GetReverse()
			zone = hn.GetReverseZone()
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
			//h.Records = append(h.Records, a.String())

			if t, ok := a.(*dns.A); ok {
				// fmt.Printf("A: %s\n", t)
				_ = h.AddHostIp(t.Hdr.Name, t.A.String())
				_ = h.LastHostname().SetRecord("A", t.String())
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
				//_ = h.AppendText(t.Txt...)
				_ = h.AddHostIp(t.Hdr.Name, "")
				_ = h.LastHostname().SetRecord("TXT", t.String())
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
				_ = h.AddHostIp(t.Hdr.Name, "")
				_ = h.LastHostname().SetRecord("SOA", t.String())
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
					_ = h.AddHostIp(t.Hdr.Name, "")
				} else {
					_ = h.AddHostIp(t.Ptr, "")
				}
				_ = h.LastHostname().SetRecord("PTR", t.String())
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

func (d *DNS) QueryAll(n string, t string) host.Hosts {
	var hs host.Hosts

	for range Only.Once {
		d.Clear()

		if n == "" {
			d.Error = errors.New("empty host / IP")
			break
		}

		h := d.Query(n, t)
		if h.Error != nil {
			break
		}
		hs = append(hs, h)

		for _, ip := range h.GetIps() {
			if ip == nil {
				continue
			}

			h = d.Query(ip.String(), t)
			if h.Error != nil {
				break
			}
			hs = append(hs, h)
		}
	}

	return hs
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

			ips := h.GetIps()
			if len(ips) == 0 {
				continue
			}
			domain := d.FindDomain(ips[0].String())
			if d.debug {
				fmt.Printf("########################################\n")
				fmt.Printf("# Host: %v", h)
				//fmt.Printf("# Domain: %s\n", domain)
				fmt.Printf("########################################\n")
			}

			d.Error = d.SyncHost(domain, &h)
			if d.Error != nil {
				continue
			}
		}
	}

	return d.Error
}

func (d *DNS) SyncHost(domain string, h *host.Host) error {

	for range Only.Once {
		d.Error = h.ChangeDomain(domain)
		if d.Error != nil {
			break
		}

		d.Error = d.DelForward(h)
		if d.Error != nil {
			break
		}
		d.Error = d.AddForward(h)
		if d.Error != nil {
			break
		}

		d.Error = d.DelReverse(h)
		if d.Error != nil {
			break
		}
		d.Error = d.AddReverse(h)
		if d.Error != nil {
			break
		}

		txt := fmt.Sprintf("%s", h.GetText())
		if h.Mac.String() != "" {
			txt = fmt.Sprintf("MacAddress:%s\nPort:%d\nTTL:%d\nService:%s\nInstance:%s\nText:%s\n",
				h.Mac.String(),
				h.Port,
				h.TTL,
				h.Service,
				h.Instance,
				h.Text)
		}

		d.Error = d.AddTxt(h, txt)
		if d.Error != nil {
			break
		}

		if d.MirrorDomain == "" {
			break
		}

		d.Error = h.ChangeDomain(d.MirrorDomain)
		if d.Error != nil {
			break
		}

		d.Error = d.DelReverse(h)
		if d.Error != nil {
			break
		}
		d.Error = d.AddReverse(h)
		if d.Error != nil {
			break
		}
	}

	if d.Error != nil {
		fmt.Printf("Sync error: %s\n", d.Error)
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

		d.Error = d.AddReverse(h)
		if d.Error != nil {
			break
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

		d.Error = d.DelForward(h)
		if d.Error != nil {
			break
		}

		d.Error = d.DelReverse(h)
		if d.Error != nil {
			break
		}
	}

	return d.Error
}

func (d *DNS) DeleteAll(n string) error {

	for range Only.Once {
		names := []string{n}
		if d.MirrorDomain != "" {
			names = append(names, host.ChangeDomain(n, d.MirrorDomain))
		}
		for _, name := range names {
			for _, q := range d.QueryAll(name, "ANY") {
				for _, hn := range q.HostNames {
					if hn.GetDomain() == "" {
						continue
					}

					d.Clear()
					if hn.GetForwardZone() != "" {
						d.Domain.FQDN = hn.GetForwardZone()
						d.msg.SetUpdate(hn.GetForwardZone())
						{
							request := dns.ANY{
								Hdr: dns.RR_Header{
									Name:   hn.GetFQDN(),
									Rrtype: dns.TypeANY,
									Class:  dns.ClassINET,
									Ttl:    q.GetTtl(),
								},
							}
							fmt.Printf("Deleting host zone(%s): %s\n", hn.GetDomain(), hn.GetFQDN())
							d.msg.RemoveName([]dns.RR{&request})
						}
					}
					d.Error = d.Execute()
					if d.Error != nil {
						fmt.Printf("Error updating: %s\n", d.Error)
					}
				}

				for _, hn := range q.HostNames {
					if hn.GetDomain() == "" {
						continue
					}

					d.Clear()
					if hn.GetReverseZone() != "" {
						d.Domain.FQDN = hn.GetReverseZone()
						d.msg.SetUpdate(hn.GetReverseZone())
						request := dns.ANY{
							Hdr: dns.RR_Header{
								Name:   hn.GetReverse(),
								Rrtype: dns.TypeANY,
								Class:  dns.ClassINET,
								Ttl:    q.GetTtl(),
							},
						}
						fmt.Printf("Deleting host zone(%s): %s\n", hn.GetDomain(), hn.GetFQDN())
						d.msg.RemoveName([]dns.RR{&request})
					}
					d.Error = d.Execute()
					if d.Error != nil {
						fmt.Printf("Error updating: %s\n", d.Error)
					}
				}
			}
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

		for _, hn := range h.HostNames {
			d.Clear()
			d.msg.SetUpdate(hn.GetDomain())

			request := dns.A{
				Hdr: dns.RR_Header{
					Name:   hn.GetFQDN(),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    h.GetTtl(), // 3600,
				},
				A: hn.GetIpAddr(),
			}

			_ = d.PrintLog(0, "Adding forward zone(%s)\n",
				hn.GetForwardZone(),
			)
			_ = d.PrintLog(1, "%s -> %s\n",
				hn.GetFQDN(),
				hn.GetIpAddr(),
			)

			//fmt.Printf("%s - Adding forward zone(%s): %s\n%s\t- %s\n",
			//	time.Now().Format("2006-02-01 15:04:05"),
			//	hn.GetDomain(),
			//	hn.GetFQDN(),
			//	time.Now().Format("2006-02-01 15:04:05"),
			//	hn.GetIpAddr(),
			//)
			d.msg.Insert([]dns.RR{&request})

			d.Error = d.Execute()
			if d.Error != nil {
				fmt.Printf("Error updating: %s\n", d.Error)
			}
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

		for _, hn := range h.HostNames {
			d.Clear()
			d.msg.SetUpdate(hn.GetDomain())

			request := dns.A{
				Hdr: dns.RR_Header{
					Name:   hn.GetFQDN(),
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    h.GetTtl(),
				},
				A: hn.GetIpAddr(),
			}

			_ = d.PrintLog(0, "Deleting forward zone(%s)\n",
				hn.GetForwardZone(),
			)
			_ = d.PrintLog(1, "%s -> %s\n",
				hn.GetFQDN(),
				hn.GetIpAddr(),
			)

			//fmt.Printf("%s - Deleting forward zone(%s): %s\n%s\t- %s\n",
			//	time.Now().Format("2006-02-01 15:04:05"),
			//	hn.GetFQDN(),
			//	hn.GetIpAddr(),
			//)
			d.msg.Remove([]dns.RR{&request})

			d.Error = d.Execute()
			if d.Error != nil {
				fmt.Printf("Error updating: %s\n", d.Error)
			}
		}
	}

	return d.Error
}

func (d *DNS) AddReverse(h *host.Host) error {

	for range Only.Once {
		d.Error = h.IsValid()
		if d.Error != nil {
			break
		}

		for _, hn := range h.HostNames {
			d.Clear()
			d.msg.SetUpdate(hn.GetReverseZone())

			request := dns.PTR{
				Hdr: dns.RR_Header{
					Name:     hn.GetReverse(),
					Rrtype:   dns.TypePTR,
					Class:    dns.ClassINET,
					Ttl:      h.GetTtl(),
					Rdlength: 0,
				},
				Ptr: hn.GetFQDN(),
			}

			_ = d.PrintLog(0, "Adding reverse zone(%s)\n",
				hn.GetReverseZone(),
			)
			_ = d.PrintLog(1, "%s -> %s\n",
				hn.GetReverse(),
				hn.GetFQDN(),
			)

			//fmt.Printf("%s - Adding reverse zone(%s): %s\n%s\t- %s\n",
			//	time.Now().Format("2006-02-01 15:04:05"),
			//	hn.GetReverseZone(),
			//	hn.GetReverse(),
			//	hn.GetFQDN(),
			//)
			d.msg.Insert([]dns.RR{&request})

			d.Error = d.Execute()
			if d.Error != nil {
				fmt.Printf("Error updating: %s\n", d.Error)
			}
		}
	}

	return d.Error
}

func (d *DNS) DelReverse(h *host.Host) error {

	for range Only.Once {
		d.Error = h.IsValid()
		if d.Error != nil {
			break
		}

		for _, hn := range h.HostNames {
			d.Clear()
			d.msg.SetUpdate(hn.GetReverseZone())

			request := dns.PTR{
				Hdr: dns.RR_Header{
					Name:     hn.GetReverse(),
					Rrtype:   dns.TypePTR,
					Class:    dns.ClassINET,
					Ttl:      h.GetTtl(),
					Rdlength: 0,
				},
				Ptr: hn.GetFQDN(),
			}

			_ = d.PrintLog(0, "Deleting reverse zone(%s)\n",
				hn.GetReverseZone(),
			)
			_ = d.PrintLog(1, "%s -> %s\n",
				hn.GetReverse(),
				hn.GetFQDN(),
			)

			//fmt.Printf("%s - Deleting reverse zone(%s): %s\n%s\t- %s\n",
			//	time.Now().Format("2006-02-01 15:04:05"),
			//	hn.GetReverseZone(),
			//	hn.GetReverse(),
			//	hn.GetFQDN(),
			//)
			d.msg.Remove([]dns.RR{&request})

			d.Error = d.Execute()
			if d.Error != nil {
				fmt.Printf("Error updating: %s\n", d.Error)
			}
		}
	}

	return d.Error
}

func (d *DNS) AddTxt(h *host.Host, txt string, args ...interface{}) error {

	for range Only.Once {
		if txt == "" {
			break
		}
		txt = fmt.Sprintf(txt, args...)
		txtArray := strings.Split(txt, "\n")
		//txt = strings.ReplaceAll(txt, "\n", "\t")

		for _, hn := range h.HostNames {
			d.Clear()
			d.msg.SetUpdate(hn.GetDomain())

			request := dns.TXT{
				Hdr: dns.RR_Header{
					Name:   hn.GetFQDN(),
					Rrtype: dns.TypeTXT,
					Class:  dns.ClassINET,
					Ttl:    h.GetTtl(),
				},
				Txt: txtArray,
			}

			_ = d.PrintLog(0, "Adding TXT zone(%s)\n",
				hn.GetForwardZone(),
			)
			_ = d.PrintLog(1, "%s ->\n",
				hn.GetFQDN(),
			)
			for _, st := range txtArray {
				_ = d.PrintLog(2, "%s\n",
					st,
				)
			}

			//fmt.Printf("%s - Adding TXT zone(%s): %s\n",
			//	time.Now().Format("2006-02-01 15:04:05"),
			//	hn.GetForwardZone(),
			//	hn.GetFQDN(),
			//)
			//fmt.Printf("%s\t- %s\n",
			//	time.Now().Format("2006-02-01 15:04:05"),
			//	txt,
			//)
			d.msg.Insert([]dns.RR{&request})

			d.Error = d.Execute()
			if d.Error != nil {
				fmt.Printf("Error updating: %s\n", d.Error)
			}
		}
	}

	return d.Error
}

func (d *DNS) DelTxt(h *host.Host, txt string, args ...interface{}) error {

	for range Only.Once {
		d.Error = h.IsValid()
		if d.Error != nil {
			break
		}
		if txt == "" {
			break
		}
		txt = fmt.Sprintf(txt, args...)
		txtArray := strings.Split(txt, "\n")
		txt = strings.ReplaceAll(txt, "\n", "\t")

		for _, hn := range h.HostNames {
			d.Clear()
			d.msg.SetUpdate(hn.GetForwardZone())

			request := dns.TXT{
				Hdr: dns.RR_Header{
					Name:     hn.GetFQDN(),
					Rrtype:   dns.TypeTXT,
					Class:    dns.ClassINET,
					Ttl:      h.GetTtl(),
					Rdlength: 0,
				},
				Txt: txtArray,
			}

			_ = d.PrintLog(0, "Deleting TXT zone(%s)\n",
				hn.GetForwardZone(),
				hn.GetFQDN(),
			)
			_ = d.PrintLog(1, "%s\n",
				hn.GetFQDN(),
			)

			//fmt.Printf("%s - Deleting reverse zone(%s): %s\n%s\t- %s\n",
			//	time.Now().Format("2006-02-01 15:04:05"),
			//	hn.GetReverseZone(),
			//	hn.GetReverse(),
			//	time.Now().Format("2006-02-01 15:04:05"),
			//	hn.GetFQDN(),
			//)
			d.msg.Remove([]dns.RR{&request})

			d.Error = d.Execute()
			if d.Error != nil {
				fmt.Printf("Error updating: %s\n", d.Error)
			}
		}
	}

	return d.Error
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
