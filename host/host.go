package host

import (
	"GoSyncDNS/Only"
	"fmt"
	"net"
	"strings"
)

func New() *Host {
	return &Host{
		HostNames: Hostnames{},
		Port:      0,
		Text:      nil,
		TTL:       0,
		Instance:  "",
		Service:   "",
		//Records:   nil,
		Mac:       nil,
		isForward: false,
		Error:     nil,
	}
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

//func (h *Host) Merge(src *Host) error {
//
//	for range Only.Once {
//		h.Error = h.AddHostIp(src.GetFQDN(), src.GetIpv4Addr())
//		//h.Error = h.HostNames.SetHostName(src.GetFQDN())
//		//h.Error = h.HostNames.SetIpAddr(src.GetIpv4Addr())
//		h.Error = h.SetPort(src.Port)
//		h.Error = h.AppendText(src.Text...)
//		h.Error = h.SetLowerTtl(src.TTL)
//		h.Error = h.SetInstance(src.Instance)
//		h.Error = h.SetService(src.Service)
//		h.Error = h.AppendRecords(src.Records...)
//		h.Error = h.SetMac(src.Mac.String())
//	}
//
//	return h.Error
//}

func (h *Host) String() string {
	var ret string

	if h.IsForward() {
		fmt.Printf("Forward lookup results\n")
	} else {
		fmt.Printf("Reverse lookup results\n")
	}

	//ret += fmt.Sprintf("# %s", h.HostNames)
	ret += fmt.Sprintf("\n# %v", h.HostNames)
	ret += fmt.Sprintf("\n# Port: %d", h.Port)
	ret += fmt.Sprintf("\n# Text:\n\t")
	ret += strings.Join(h.Text, "\n\t")
	ret += fmt.Sprintf("\n# TTL: %s", h.GetTtlString())
	ret += fmt.Sprintf("\n# Instance: %s", h.Instance)
	ret += fmt.Sprintf("\n# Service: %s", h.Service)
	//ret += fmt.Sprintf("\n# Records:\n\t%s", strings.Join(h.Records, "\n\t"))
	ret += fmt.Sprintf("\n# Mac: %s", h.Mac)
	ret += fmt.Sprintf("\n# isForward: %v", h.isForward)
	//ret += fmt.Sprintf("\n# Last error: %s", h.Error)

	return ret
}

func (h *Host) LastHostname() *Hostname {
	ret := h.HostNames.Last()
	if ret == nil {
		ret = &Hostname{}
		h.HostNames = append(h.HostNames, ret)
	}
	return ret
}
