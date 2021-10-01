package discover

import (
	"GoSyncDNS/Only"
	"fmt"
	"net"
	"strings"
)

type Ips map[string]Ip

func (i *Ips) Get() []string {
	var ret []string
	for _, s := range *i {
		ret = append(ret, s.Address.String())
	}
	return ret
}

func (i *Ips) GetString() string {
	return strings.Join(i.Get(), " ")
}

func (i *Ips) IsValid() bool {
	var ok bool
	for _, s := range *i {
		ok = s.IsValid()
		if ok {
			break
		}
	}
	return ok
}
func (i *Ips) IsNotValid() bool {
	return !i.IsValid()
}

func (i *Ips) Set(ip net.IP, subnet net.IPNet) error {
	var err error

	for range Only.Once {
		if sip, ok := (*i)[ip.String()]; ok {
			err = sip.Set(ip, subnet)
			break
		}

		var sip Ip
		err = sip.Set(ip, subnet)
		if err != nil {
			break
		}

		(*i)[ip.String()] = sip
	}

	return err
}

//func (i *Ips) SetAddr(ip net.IP) error {
//	var err error
//
//	for range Only.Once {
//		if ip.String() == "" {
//			//fmt.Printf("EMPTY '%v' -> '%s'\n", ip, i.String())
//			break
//		}
//
//		i = append(i, ip)
//	}
//
//	return err
//	//return i.Set(net.IPNet{IP: ip, Mask: i.Subnet.Mask})
//}
//
//func (i *Ips) SetSubnet(subnet net.IPNet) error {
//	var err error
//
//	for range Only.Once {
//		if subnet.String() == "" {
//			fmt.Printf("EMPTY '%v' -> '%v'\n", subnet, *i)
//			break
//		}
//
//		i.Subnet = subnet
//	}
//
//	return err
//}

type Ip struct {
	Subnet  net.IPNet `json:"subnet"`
	Address net.IP    `json:"address"`
}

func (i *Ip) IsValid() bool {
	var ok bool

	for range Only.Once {
		//fmt.Printf("F%s\n", i.Subnet.String())
		//if i.Subnet.Mask.String() != "" {
		//	ok = true
		//	break
		//}
		//if i.Subnet.IP.String() != "" {
		//	ok = true
		//	break
		//}
		if i.Address != nil {
			ok = true
			break
		}
	}

	return ok
}
func (i *Ip) IsNotValid() bool {
	return !i.IsValid()
}

func (i *Ip) Set(ip net.IP, subnet net.IPNet) error {
	var err error

	for range Only.Once {
		err = i.SetAddr(ip)
		if err != nil {
			break
		}

		//if ip.IsMulticast() {
		//	subnet = net.IPNet {
		//		IP:   nil,
		//		Mask: nil,
		//	}
		//}
		err = i.SetSubnet(subnet)
		if err != nil {
			break
		}
	}

	return err
}

func (i *Ip) SetAddr(ip net.IP) error {
	var err error

	for range Only.Once {
		//if ip.Equal(broadcastIP) {
		//	fmt.Printf("BROADCAST '%v' -> '%v'\n", ip, *i)
		//	break
		//}

		if ip.String() == "" {
			//fmt.Printf("EMPTY '%v' -> '%s'\n", ip, i.String())
			break
		}

		if i.Address != nil {
			fmt.Printf("ALREADY SET '%v' -> '%s'\n", ip, i.String())
		} else {
			//fmt.Printf("SET %v\n", ip)
		}

		i.Address = ip
	}

	return err
	//return i.Set(net.IPNet{IP: ip, Mask: i.Subnet.Mask})
}

func (i *Ip) SetString(ip string) error {
	var err error

	for range Only.Once {
		var i2 net.IP
		var is *net.IPNet
		i2, is, err = net.ParseCIDR(ip)
		if err != nil {
			break
		}

		err = i.SetSubnet(*is)
		if err != nil {
			break
		}

		err = i.SetAddr(i2)
		if err != nil {
			break
		}
	}

	return err
}

func (i *Ip) SetAddrString(ip string) error {
	return i.SetAddr(net.ParseIP(ip))
}

func (i *Ip) SetSubnet(subnet net.IPNet) error {
	var err error

	for range Only.Once {
		//if subnet.String() == BroadcastIP.String() {
		//	fmt.Printf("BROADCAST '%v' -> '%v'\n", subnet, *i)
		//	break
		//}

		if subnet.String() == "" {
			fmt.Printf("EMPTY '%v' -> '%s'\n", subnet, i.String())
			break
		}

		if i.Subnet.IP != nil {
			fmt.Printf("ALREADY SET '%v' -> '%s'\n", subnet, i.String())
		} else {
			//fmt.Printf("SET %v\n", subnet)
		}

		i.Subnet = subnet
	}

	return err
	//return i.Set(net.IPNet{IP: ip, Mask: i.Subnet.Mask})
}

//func (i *Ip) SetByIPNet(ip net.IPNet) error {
//	return i.Set(net.ParseIP(ip.IP.String()))
//}

//func (i *Ip) SetMask(n net.IPMask) error {
//	return i.Set(net.IPNet{IP: i.Address, Mask: n})
//}

func (i *Ip) Get() net.IP {
	return i.Address.To4()
}

func (i *Ip) IsSameSubnet(subnet net.IPNet) bool {
	var ok bool

	for range Only.Once {
		if i.Subnet.Mask.String() == subnet.Mask.String() {
			ok = true
			break
		}
	}

	return ok
}

func (i *Ip) GetMask() net.IPMask {
	var ret net.IPMask
	for range Only.Once {
		if i.Subnet.Mask != nil {
			ret = i.Subnet.Mask
			break
		}

		//if !i.Address.Equal(broadcastIP) {
		//	break
		//}

		ret = net.IPMask(i.Address)
	}
	return ret
}

func (i *Ip) GetSubnet() net.IP {
	return i.Subnet.IP.To4()
}

func (i *Ip) Equals(ip net.IP) bool {
	var ok bool
	if i.Address.String() == ip.String() {
		ok = true
	}
	return ok
}

func (i *Ip) NotEquals(ip net.IP) bool {
	return !i.Equals(ip)
}

func (i *Ip) String() string {
	return fmt.Sprintf("%s", i.Address.String())
}
