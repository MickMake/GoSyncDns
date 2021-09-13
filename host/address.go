package host

import (
	"GoSyncDNS/Only"
	"errors"
	"fmt"
	"net"
	"regexp"
)

type Addresses []Address
type Address struct {
	AddrIPv4    net.IP `json:"-"` // Host machine IPv4 address
	AddrIPv6    net.IP `json:"-"` // Host machine IPv6 address
	ForwardZone string
	ReverseZone string
	Reverse     string
	SubNet      *net.IPNet

	Error error
}

func (a *Address) String() string {
	var ret string
	ret += "\n################"
	if a.AddrIPv4 != nil {
		ret += fmt.Sprintf("\n# AddrIPv4: %s", a.AddrIPv4.String())
	}
	if a.AddrIPv6 != nil {
		ret += fmt.Sprintf("\n# AddrIPv6: %s", a.AddrIPv6.String())
	}
	if a.SubNet != nil {
		ret += fmt.Sprintf("\n# SubNet: %s", a.SubNet.String())
	}
	ret += fmt.Sprintf("\n# Forward Zone: %s", a.ForwardZone)
	ret += fmt.Sprintf("\n# Reverse Zone: %s", a.ReverseZone)
	ret += fmt.Sprintf("\n# Reverse Host: %s", a.Reverse)
	return ret
}

func (a *Address) SetIpAddr(ip string) error {
	for range Only.Once {
		if ip == "" {
			a.Error = errors.New("empty IP address")
			break
		}

		a.AddrIPv4 = net.ParseIP(ip).To4()

		if a.AddrIPv4.String() == "" {
			a.Error = errors.New("invalid IP address")
			break
		}

		a.Error = a.ParseReverse(ip)
		if a.Error != nil {
			break
		}

		a.Error = a.ParseSubnet(ip + "/24") // @TODO - hackety hack.
		if a.Error != nil {
			break
		}
	}

	return a.Error
}

func (a *Address) SetIpv6Addr(ip string) error {
	for range Only.Once {
		break
		if ip == "" {
			a.Error = errors.New("empty IP address")
			break
		}

		a.AddrIPv6 = net.ParseIP(ip).To4()

		if a.AddrIPv6.String() == "" {
			a.Error = errors.New("invalid IP address")
			break
		}

		a.Error = a.ParseReverse(ip)
		if a.Error != nil {
			break
		}

		a.Error = a.ParseSubnet(ip + "/24") // @TODO - hackety hack.
		if a.Error != nil {
			break
		}
	}

	return a.Error
}

func (a *Address) ParseReverse(ip string) error {

	for range Only.Once {
		if ip == "" {
			break
		}

		a.AddrIPv4 = net.ParseIP(ip)
		a.Reverse, a.Error = ReverseAddr(a.AddrIPv4.String())
		reg := regexp.MustCompile(`^\d+\.`)
		a.ReverseZone = reg.ReplaceAllString(a.Reverse, "")
	}

	return a.Error
}

func (a *Address) ParseSubnet(ip string) error {

	for range Only.Once {
		if ip == "" {
			break
		}

		_, a.SubNet, a.Error = net.ParseCIDR(ip)
		//reg := regexp.MustCompile(`\.\d+$`)
		//a.Address.SubNet = reg.ReplaceAllString(a.Address.ReverseZone, "")
	}

	return a.Error
}

//func (a *Address) SetReverseZone(rev string) error {
//	for range Only.Once {
//	}
//
//	return a.Error
//}
