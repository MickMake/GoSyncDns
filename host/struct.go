package host

import (
	"GoSyncDNS/Only"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type Hosts []Host

type Host struct {
	HostName Hostname `json:"hostname"` // Host machine DNS name
	Port     int      `json:"port"`     // Service Port
	Text     []string `json:"text"`     // Service info served as a TXT record
	TTL      uint32   `json:"ttl"`      // TTL of the service record
	Instance string   `json:"name"`     // Instance name (e.g. "My web page")
	Service  string   `json:"type"`     // Service name (e.g. _http._tcp.)
	Address  Address
	Records  Records

	Mac net.HardwareAddr `json:"mac"`

	isForward bool
	Error     error
}

type Records []string

//type Records map[string]string
type Addresses []Address
type Address struct {
	AddrIPv4    net.IP `json:"-"` // Host machine IPv4 address
	AddrIPv6    net.IP `json:"-"` // Host machine IPv6 address
	ForwardZone string
	ReverseZone string
	Reverse     string
	SubNet      *net.IPNet
}

func (d *Address) String() string {
	ret := fmt.Sprintf("\n# AddrIPv4: %s\n# AddrIPv6: %s\n# Forward Zone: %s\n# Reverse Zone: %s\n# Reverse Host: %s\n# SubNet: %s",
		d.AddrIPv4.String(),
		d.AddrIPv6.String(),
		d.ForwardZone,
		d.ReverseZone,
		d.Reverse,
		d.SubNet.String(),
	)
	return ret
}

func (h *Host) IsValid() error {
	for range Only.Once {
		if h.HostName.Name == "" {
			h.Error = errors.New("empty host name")
			break
		}

		if h.HostName.Domain == "" {
			h.Error = errors.New("empty domain name")
			break
		}

		if h.HostName.FQDN == "" {
			h.Error = errors.New("empty FQDN")
			break
		}

		if (h.Address.AddrIPv4.String() == "") && (h.Address.AddrIPv6.String() == "") {
			h.Error = errors.New("empty IP address")
			break
		}

		//if h.Address.ForwardZone == "" {
		//	h.Error = errors.New("empty forward zone")
		//	break
		//}
		//
		//if h.Address.ReverseZone == "" {
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

func (h *Host) HasAnIp() bool {
	if h.Address.AddrIPv4.String() != "" {
		return true
	}
	if h.Address.AddrIPv6.String() != "" {
		return true
	}
	return false
}
func (h *Host) NoIp() bool {
	return !h.HasAnIp()
}

func (h *Host) Set(name string) error {
	for range Only.Once {
		if IsIpAddress(name) {
			h.Error = h.SetIpAddr(name)
			break
		}

		h.Error = h.SetHostName(name)
	}
	return h.Error
}

func (h *Host) SetHostName(fqdn string) error {
	for range Only.Once {
		h.Error = h.HostName.SetHostName(fqdn)
		if h.Error != nil {
			break
		}

		h.Address.ForwardZone = h.GetDomain()
	}
	return h.Error
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

func (h *Host) SetIpAddr(ip string) error {

	for range Only.Once {
		if ip == "" {
			h.Error = errors.New("empty IP address")
			break
		}

		h.Address.AddrIPv4 = net.ParseIP(ip)

		if h.Address.AddrIPv4.String() == "" {
			h.Error = errors.New("invalid IP address")
			break
		}

		h.Error = h.ParseReverse(ip)
		if h.Error != nil {
			break
		}

		h.Error = h.ParseSubnet(ip + "/24") // @TODO - hackety hack.
		if h.Error != nil {
			break
		}
	}

	return h.Error
}

func (h *Host) SetIpv6Addr(ip string) error {

	for range Only.Once {
		if ip == "" {
			break
		}

		h.Address.AddrIPv6 = net.ParseIP(ip)
	}

	return h.Error
}

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

func (h *Host) SetRecords(txt ...string) error {

	for range Only.Once {
		h.Records = txt
	}

	return h.Error
}

func (h *Host) AppendRecords(txt ...string) error {

	for range Only.Once {
		h.Records = append(h.Records, txt...)
	}

	return h.Error
}

func (h *Host) ChangeDomain(domain string) error {
	return h.HostName.ChangeDomain(domain)
}

func (h *Host) GetName() string {
	return h.HostName.GetName()
}

func (h *Host) GetDomain() string {
	return h.HostName.GetDomain()
}

func (h *Host) GetFQDN() string {
	return h.HostName.GetFQDN()
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

func (h *Host) GetIpAddr() net.IP {
	if h.Address.AddrIPv4.String() != "" {
		return h.Address.AddrIPv4
	}
	return h.Address.AddrIPv6
}

func (h *Host) GetIpv4Addr() string {
	return h.Address.AddrIPv4.String()
}

func (h *Host) GetIpv6Addr() string {
	return h.Address.AddrIPv6.String()
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

func (h *Host) GetReverseZone() string {
	return h.Address.ReverseZone
}

func (h *Host) GetForwardZone() string {
	return h.Address.ForwardZone
}

func (h *Host) GetReverse() string {
	return h.Address.Reverse
}
