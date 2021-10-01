package discover

import (
	"GoSyncDNS/Only"
	"encoding/json"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/google/gopacket/layers"
	"net"
	"time"
)

type FoundHosts struct {
	Current  Hosts
	Historic []Host
}

func (h *FoundHosts) Add(host Host) error {
	var err error

	for range Only.Once {
		if host.IsNotValid() {
			break
		}

		if hStruct, ok := h.Current[host.GetMac()]; ok {
			h.Historic = append(h.Historic, hStruct)
			err = hStruct.Update(host)
			break
		}

		fmt.Printf("# ADD - %s %s\n", host.Mac.String(), host.Ips.GetString())
		host.When = time.Now()
		h.Current[host.GetMac()] = host
		_ = host.Print()
	}

	return err
}

//type Hosts map[Mac]Host
type MacAddress string
type Hosts map[MacAddress]Host
type Host struct {
	When         time.Time `json:"when"`
	IsDhcpServer bool      `json:"dhcp_server"`
	Mac          Mac       `json:"mac"`
	Ips          Ips       `json:"ips"`
	//SubnetMask Ip         `json:"subnet"`
	Options  DhcpOptions `json:"options"`
	HostName string      `json:"hostname"`
	dhcp     *layers.DHCPv4
	Src      bool
	//Str string
}

func NewHost() *Host {
	var h Host
	h.Ips = make(Ips)
	h.When = time.Now()
	return &h
}
func (h *Host) IsValid() bool {
	ok := true

	for range Only.Once {
		if h == nil {
			ok = false
			break
		}

		//if h.Ip.IsNotValid() && h.Mac.IsNotValid() {
		if h.Mac.IsNotValid() {
			ok = false
			break
		}
	}

	return ok
}
func (h *Host) IsNotValid() bool {
	return !h.IsValid()
}

func (h *Host) Update(host Host) error {
	var err error

	for range Only.Once {
		h.When = time.Now()
		if host.Ips.IsValid() {
			h.Ips = host.Ips
		}
		if host.Mac.IsValid() {
			h.Mac = host.Mac
		}
		if host.HostName != "" {
			h.HostName = host.HostName
		}
		if host.Options.Hostname != "" {
			h.HostName = host.Options.Hostname
		}
		if host.dhcp != nil {
			h.dhcp = host.dhcp
		}
		//if host.Options != nil {
		//	h.Options = host.Options
		//}
		fmt.Printf("# UPDATE - %s %s\n", host.Mac.String(), host.Ips.GetString())
		_ = host.Print()
	}

	return err
}

func (h *Host) Print() error {
	var err error

	for range Only.Once {
		var j []byte

		j, err = json.Marshal(h)
		if err != err {
			fmt.Printf("Error: \n", err)
			spew.Dump(h)
			break
		}
		fmt.Printf("%s\n", j)
	}

	return err
}

func (h *Host) GetMac() MacAddress {
	return h.Mac.GetMac()
}

func (h *Host) GetHardwareAddr() net.HardwareAddr {
	return net.HardwareAddr(h.Mac.GetMac())
}
