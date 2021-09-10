package host

import (
	"GoSyncDNS/Only"
	"fmt"
	"net"
	"regexp"
	"strings"
)

func New() *Host {
	var h Host
	return &h
}

func IsIpAddress(ip string) bool {
	var ok bool

	for range Only.Once {
		if ip == "" {
			break
		}

		ip := net.ParseIP(ip)

		if ip.String() == "" {
			break
		}

		if ip == nil {
			break
		}

		ok = true
	}

	return ok
}

type RevHostname struct {
	Name string
	Zone string
}

func (h *Host) ParseReverse(ip string) error {

	for range Only.Once {
		if ip == "" {
			break
		}

		h.Address.AddrIPv4 = net.ParseIP(ip)
		h.Address.Reverse, h.Error = ReverseAddr(h.Address.AddrIPv4.String())
		reg := regexp.MustCompile(`^\d+\.`)
		h.Address.ReverseZone = reg.ReplaceAllString(h.Address.Reverse, "")
	}

	return h.Error
}

func (h *Host) ParseSubnet(ip string) error {

	for range Only.Once {
		if ip == "" {
			break
		}

		_, h.Address.SubNet, h.Error = net.ParseCIDR(ip)
		//reg := regexp.MustCompile(`\.\d+$`)
		//h.Address.SubNet = reg.ReplaceAllString(h.Address.ReverseZone, "")
	}

	return h.Error
}

func (h *Host) Merge(src *Host) error {

	for range Only.Once {
		h.Error = h.HostName.SetHostName(src.GetFQDN())
		h.Error = h.SetPort(src.Port)
		h.Error = h.AppendText(src.Text...)
		h.Error = h.SetLowerTtl(src.TTL)
		h.Error = h.SetInstance(src.Instance)
		h.Error = h.SetService(src.Service)
		h.Error = h.SetIpAddr(src.GetIpv4Addr())
		h.Error = h.AppendRecords(src.Records...)
		h.Error = h.SetMac(src.Mac.String())
	}

	return h.Error
}

func (h *Host) String() string {
	var ret string

	if h.IsForward() {
		fmt.Printf("Forward lookup results\n")
	} else {
		fmt.Printf("Reverse lookup results\n")
	}

	ret += fmt.Sprintf("# %s", h.HostName.String())
	ret += fmt.Sprintf("# Port: %d", h.Port)
	ret += fmt.Sprintf("\n# Text:\n\t%s", strings.Join(h.Text, "\n\t"))
	ret += fmt.Sprintf("\n# TTL: %s", h.GetTtlString())
	ret += fmt.Sprintf("\n# Instance: %s", h.Instance)
	ret += fmt.Sprintf("\n# Service: %s", h.Service)
	ret += fmt.Sprintf("\n# %s", h.Address.String())
	ret += fmt.Sprintf("\n# Records:\n\t%s", strings.Join(h.Records, "\n\t"))
	ret += fmt.Sprintf("\n# Mac: %s", h.Mac)
	ret += fmt.Sprintf("\n# isForward: %v", h.isForward)
	//ret += fmt.Sprintf("\n# Last error: %s", h.Error)

	return ret
}
