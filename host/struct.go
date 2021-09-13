package host

import (
	"GoSyncDNS/Only"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Hosts []*Host

type Host struct {
	HostNames Hostnames        `json:"hostnames"` // Host machine DNS names
	Port      int              `json:"port"`      // Service Port
	Text      []string         `json:"text"`      // Service info served as a TXT record
	TTL       uint32           `json:"ttl"`       // TTL of the service record
	Instance  string           `json:"name"`      // Instance name (e.g. "My web page")
	Service   string           `json:"type"`      // Service name (e.g. _http._tcp.)
	Mac       net.HardwareAddr `json:"mac"`

	//Records  []Record

	isForward bool
	Error     error
}

type Record struct {
	Type   string
	String string
}

//type Records map[string]string

func (h *Host) IsValid() error {
	for range Only.Once {
		//if h.HostNames.Name == "" {
		//	h.Error = errors.New("empty host name")
		//	break
		//}
		//
		//if h.HostNames.Domain == "" {
		//	h.Error = errors.New("empty domain name")
		//	break
		//}
		//
		//if h.HostNames.FQDN == "" {
		//	h.Error = errors.New("empty FQDN")
		//	break
		//}
		//
		//if (h.HostNames.Address.AddrIPv4.String() == "") && (h.HostNames.Address.AddrIPv6.String() == "") {
		//	h.Error = errors.New("empty IP address")
		//	break
		//}

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

func (h *Host) IsForward() bool {
	return h.isForward
}
func (h *Host) SetForward() {
	h.isForward = true
}
func (h *Host) SetReverse() {
	h.isForward = false
}

func (h *Host) GetIps() []net.IP {
	var ret []net.IP
	for range Only.Once {
		ips := make(map[string]net.IP)
		for _, hn := range h.HostNames {
			if hn.Address.AddrIPv4.String() != "" {
				ips[hn.Address.AddrIPv4.String()] = hn.Address.AddrIPv4
			}
			if hn.Address.AddrIPv6.String() != "" {
				ips[hn.Address.AddrIPv6.String()] = hn.Address.AddrIPv6
			}
		}

		for _, ip := range ips {
			if ip == nil {
				continue
			}
			ret = append(ret, ip)
		}
	}
	return ret
}

func (h *Host) Set(name string) error {
	for range Only.Once {
		if IsIpAddress(name) {
			h.Error = h.AddHostIp("", name)
			break
		}

		h.Error = h.AddHostIp(name, "")
	}
	return h.Error
}

func (h *Host) AddHostIp(fqdn string, ip string) error {
	for range Only.Once {
		if h.hostExists(fqdn, ip) {
			break
		}

		hn := &Hostname{}
		h.HostNames = append(h.HostNames, hn)
		if fqdn != "" {
			//h.HostNames = append(h.HostNames, hn)
			h.Error = hn.SetHostName(fqdn)
			if h.Error != nil {
				break
			}
		}

		if ip != "" {
			h.Error = hn.SetIpAddr(ip)
			if h.Error != nil {
				break
			}
		}
	}
	return h.Error
}

//func (h *Host) SetHostName(fqdn string) error {
//	ddsd
//	for range Only.Once {
//		if h.HostNames.FQDN == "" {
//			h.Error = h.HostNames.SetHostName(fqdn)
//			if h.Error != nil {
//				break
//			}
//			h.HostNames.Address.ForwardZone = h.GetDomain()
//			break
//		}
//
//		if h.Exists(fqdn) {
//			break
//		}
//
//		a := h.AddAlias()
//		h.Error = a.SetHostName(fqdn)
//		if h.Error != nil {
//			break
//		}
//		a.Address.ForwardZone = h.GetDomain()
//	}
//	return h.Error
//}
//
//func (h *Host) addAlias() *Hostname {
//	var ret Hostname
//	h.Aliases = append(h.Aliases, &ret)
//	return &ret
//}
//
//func (h *Host) getNext(fqdn string, ip string) *Hostname {
//	ret := &Hostname{}
//	for range Only.Once {
//		if h.HostNames == nil {
//			h.HostNames = ret
//			break
//		}
//
//		if h.hostExists(fqdn) {
//
//		}
//	}
//	return ok
//}

func (h *Host) hostExists(fqdn string, ip string) bool {
	return h.HostNames.HostExists(fqdn, ip)
}

func (h *Host) SetPortString(port string) error {
	for range Only.Once {
		if port == "" {
			break
		}

		h.Port, h.Error = strconv.Atoi(port)
		if h.Error != nil {
			break
		}
	}

	return h.Error
}
func (h *Host) SetPort(port int) error {
	for range Only.Once {
		if port == 0 {
			break
		}

		h.Port = port
	}

	return h.Error
}

func (h *Host) SetText(txt ...string) error {

	for range Only.Once {
		//if len(txt) == 0 {
		//	break
		//}
		//h.Text = strings.Join(txt, " ")
		h.Text = txt
	}

	return h.Error
}

func (h *Host) AppendText(txt ...string) error {

	for range Only.Once {
		h.Text = append(h.Text, txt...)
	}

	return h.Error
}

func (h *Host) SetTtl(ttl uint32) error {

	for range Only.Once {
		h.TTL = ttl
	}

	return h.Error
}

func (h *Host) SetLowerTtl(ttl uint32) error {
	for range Only.Once {
		if ttl < h.TTL {
			h.TTL = ttl
		}
	}

	return h.Error
}

func (h *Host) SetHigherTtl(ttl uint32) error {

	for range Only.Once {
		if ttl > h.TTL {
			h.TTL = ttl
		}
	}

	return h.Error
}

func (h *Host) SetTtlString(ttl string) error {

	for range Only.Once {
		if ttl == "" {
			ttl = "3600"
		}

		var t uint64
		t, h.Error = strconv.ParseUint(ttl, 10, 32)
		if h.Error != nil {
			break
		}
		h.TTL = uint32(t)
	}

	return h.Error
}

//func (h *Host) SetIpAddr(ip string) error {
//
//	for range Only.Once {
//		if ip == "" {
//			h.Error = errors.New("empty IP address")
//			break
//		}
//
//		h.HostNames.Address.AddrIPv4 = net.ParseIP(ip)
//
//		if h.HostNames.Address.AddrIPv4.String() == "" {
//			h.Error = errors.New("invalid IP address")
//			break
//		}
//
//		h.Error = h.ParseReverse(ip)
//		if h.Error != nil {
//			break
//		}
//
//		h.Error = h.ParseSubnet(ip + "/24") // @TODO - hackety hack.
//		if h.Error != nil {
//			break
//		}
//	}
//
//	return h.Error
//}
//
//func (h *Host) SetIpv6Addr(ip string) error {
//
//	for range Only.Once {
//		if ip == "" {
//			break
//		}
//
//		h.HostNames.Address.AddrIPv6 = net.ParseIP(ip)
//	}
//
//	return h.Error
//}

func (h *Host) SetInstance(txt ...string) error {

	for range Only.Once {
		if len(txt) == 0 {
			break
		}

		h.Instance = strings.Join(txt, " ")
	}

	return h.Error
}

func (h *Host) SetService(txt ...string) error {

	for range Only.Once {
		if len(txt) == 0 {
			break
		}

		h.Instance = strings.Join(txt, ".")
	}

	return h.Error
}

func (h *Host) SetMac(mac string) error {

	for range Only.Once {
		if mac == "" {
			break
		}

		h.Mac, h.Error = net.ParseMAC(mac)
	}

	return h.Error
}

func (h *Host) GetPort() int {
	return h.Port
}

func (h *Host) GetText() string {
	return strings.Join(h.Text, "\n")
}

func (h *Host) GetTtl() uint32 {
	var ret uint32
	if h.TTL == 0 {
		h.TTL = 3600
	}
	return ret
}

func (h *Host) GetTtlString() string {
	ttl, _ := time.ParseDuration(fmt.Sprintf("%d seconds", h.TTL))
	return ttl.String()
}

func (h *Host) GetIpAddrs() []net.IP {
	ret := h.GetIpv4Addrs()
	ret = append(ret, h.GetIpv6Addrs()...)
	return ret
}

func (h *Host) GetIpv4Addrs() []net.IP {
	var ret []net.IP
	for _, ip := range h.HostNames {
		ret = append(ret, ip.Address.AddrIPv4)
	}
	return ret
}

func (h *Host) GetIpv6Addrs() []net.IP {
	var ret []net.IP
	for _, ip := range h.HostNames {
		ret = append(ret, ip.Address.AddrIPv6)
	}
	return ret
}

func (h *Host) GetInstance() string {
	return h.Instance
}

func (h *Host) GetService() string {
	return h.Service
}

func (h *Host) GetMac() string {
	return h.Mac.String()
}

func (h *Host) ChangeDomain(domain string) error {
	for _, hn := range h.HostNames {
		h.Error = hn.ChangeDomain(domain)
	}
	return h.Error
}

//func (h *Host) GetName() string {
//	return h.HostNames.GetName()
//}
//
//func (h *Host) GetDomain() string {
//	return h.HostNames.GetDomain()
//}
//
//func (h *Host) GetFQDN() string {
//	return h.HostNames.GetFQDN()
//}
//
//func (h *Host) GetReverseZone() string {
//	return h.HostNames.GetReverseZone()
//}
//
//func (h *Host) GetForwardZone() string {
//	return h.HostNames.GetForwardZone()
//}
//
//func (h *Host) GetReverse() string {
//	return h.HostNames.GetReverse()
//}
