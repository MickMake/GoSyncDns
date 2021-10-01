package discover

import (
	"GoSyncDNS/Only"
	"fmt"
	"github.com/golang/glog"
	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"net"
	"time"
)

type Interface struct {
	*net.Interface
	//net.Addr
	Mac Mac
	IP  Ip

	FoundHosts FoundHosts
	handle     *pcap.Handle
}

func (i *Interface) GetMac() net.HardwareAddr {
	return i.Mac.Get()
}

func (i *Interface) GetIp() net.IP {
	return i.IP.Get()
}

func (i *Interface) GetMask() net.IPMask {
	return i.IP.GetMask()
}

func (i *Interface) GetSubnet() net.IP {
	return i.IP.GetSubnet()
}

//type Interface struct {
//	Interface  Interface
//}
type Interfaces []Interface

func (i *Interface) ScanNetwork(t time.Duration) error {
	var err error

	for range Only.Once {
		fmt.Printf("# Scanning interface %s (%s)\n", i.Interface.Name, i.Interface.HardwareAddr.String())
		if t == 0 {
			t = time.Second
		}

		//err = setLayer(net.HardwareAddr(i.Interface.MacAddress), i.Interface.IP.IP)
		err = setLayer(*i)
		if err != nil {
			glog.Warningf("set layer on %s fail: %s", i.Interface.Name, err)
			break
		}

		i.handle, err = pcap.OpenLive(i.Interface.Name, 65536, true, t)
		if i.handle == nil {
			glog.Warningf("pcap open live on %s fail: %s", i.Interface.Name, err)
			break
		}
		//defer i.handle.Close()
		if err != nil {
			glog.Warningf("pcap open live on %s fail: %s", i.Interface.Name, err)
			break
		}

		// err = handle.SetBPFFilter("ether dst " + i.Interface.HardwareAddr.String())
		// err = handle.SetBPFFilter("ether dst ff:ff:ff:ff:ff:ff")
		// err = handle.SetBPFFilter("port 67 or port 68 or arp")
		err = i.handle.SetBPFFilter("port 67 or port 68")
		if err != nil {
			glog.Warningf("set bpf on %s fail: %s", i.Interface.Name, err)
			break
		}

		// send discover message
		go func() {
			var err error
			for range Only.Thrice {
				time.Sleep(time.Second * 3)
				err = i.DiscoverDhcpServers(t)
				if err != nil {
					glog.Warningf("pcap serialize layers fail: %s", err)
				}
			}
		}()

		// receive dhcp message
		src := gopacket.NewPacketSource(i.handle, i.handle.LinkType())
		for packet := range src.Packets() {
			err = i.ParsePacket(packet)
			if err != nil {
				break
			}
		}

		// src := gopacket.NewPacketSource(handle, layers.LayerTypeEthernet)
		// for {
		// 	fmt.Printf(".")
		// 	pack, err := src.NextPacket()
		// 	if err != nil {
		// 		if err != io.EOF {
		// 			glog.Warningf("read pack from %s fail: %s", iface.Name, err)
		// 		}
		// 	}
		// 	// if pack == nil {
		// 	// 	break
		// 	// }
		// 	fmt.Printf("PACK: %v\n",
		// 		pack,
		// 		// pack.ApplicationLayer().LayerType().String(),
		// 	)
		//
		// 	layer := pack.Layer(layers.LayerTypeDHCPv4)
		// 	if layer != nil {
		// 		dhcp4 := layer.(*layers.DHCPv4)
		// 		fmt.Printf("DHCP4: %s (%s)\n",
		// 			dhcp4.ClientIP.String(),
		// 			dhcp4.ClientHWAddr.String(),
		// 			)
		// 		for i := range dhcp4.Options {
		// 			if dhcp4.Options[i].Type != layers.DHCPOptDNS {
		// 				continue
		// 			}
		//
		// 			data := dhcp4.Options[i].Data
		// 			fmt.Printf("DATA: %v\n", data)
		// 			if len(data) >= net.IPv4len {
		// 				fmt.Printf("LAYER: %v\n-\t%v\n-\t%v\n",
		// 					layer.LayerType(),
		// 					layer.LayerPayload(),
		// 					layer.LayerContents(),
		// 					)
		// 				fmt.Printf("%s\n", net.IPv4(data[0], data[1], data[2], data[3]).String())
		// 			}
		// 		}
		// 	}
		// }

		//time.Sleep(t)
		//fmt.Printf("END\n")
	}

	return err
}

func (i *Interface) ScanClose() {
	i.handle.Close()
}

func (i *Interface) DiscoverDhcpServers(t time.Duration) error {
	var err error

	for range Only.Once {
		if i.handle == nil {
			break
		}

		fmt.Printf("# Discver DHCP servers on interface %s (%s)\n", i.Interface.Name, i.Interface.HardwareAddr.String())

		// send discover message
		buff := gopacket.NewSerializeBuffer()
		err = gopacket.SerializeLayers(buff, opts, ethLayer, ipLayer, udpLayer, dhcp4Layer)
		if err != nil {
			break
		}

		err = i.handle.WritePacketData(buff.Bytes())
		if err != nil {
			break
		}
	}

	return err
}

func (i *Interface) String() string {
	var ret string

	for range Only.Once {
		ret += fmt.Sprintf("%s (%s):	%s	%s\n",
			i.Interface.Name,
			i.Mac.String(),
			//i.Interface.HardwareAddr.String(),
			i.IP.Address.String(),
			i.IP.Subnet.String(),
			//i.Interface.IP.Subnet.IP.String(),
			//i.Interface.IP.Subnet.Mask.String(),
		)
	}

	return ret
}

func (i *Interface) ParsePacket(packet gopacket.Packet) error {
	var err error

	for range Only.Once {
		src := NewHost()
		dst := NewHost()
		src.Src = true

		if i.FoundHosts.Current == nil {
			i.FoundHosts.Current = make(map[MacAddress]Host)
		}

		fmt.Println("\n################################################################################")
		var p Packet
		err = p.Parse(packet)
		if err != nil {
			break
		}

		subnet := p.DiscoverSubnet()
		//if !i.IP.IsSameSubnet(*subnet) {
		//	fmt.Printf("# WARNING Net doesn't match: %s != %s\n", subnet.String(), i.IP.Subnet.String())
		//}
		if subnet == nil {
			subnet = &i.IP.Subnet
		}

		//fmt.Printf("Packet - IP: %s -> %s\n\t- mac: %s -> %s\n",
		//	p.ipLayer.SrcIP,
		//	p.ipLayer.DstIP,
		//	p.ethernetLayer.SrcMAC,
		//	p.ethernetLayer.DstMAC,
		//)

		if p.ethernetLayer != nil {
			_ = src.Mac.Set(p.ethernetLayer.SrcMAC)
			_ = dst.Mac.Set(p.ethernetLayer.DstMAC)
			fmt.Printf("# From MAC %s to %s\n", p.ethernetLayer.SrcMAC, p.ethernetLayer.DstMAC)
		}

		if p.ipLayer != nil {
			_ = src.Ips.Set(p.ipLayer.SrcIP, *subnet)
			_ = dst.Ips.Set(p.ipLayer.DstIP, *subnet)
			fmt.Printf("# From IP %s to %s\n", p.ipLayer.SrcIP, p.ipLayer.DstIP)
		}

		if p.arpLayer != nil {
			p.PrintArp()
		}

		if p.dhcpLayer != nil {
			dh := NewHost()
			_ = dh.Mac.Set(p.dhcpLayer.ClientHWAddr)
			_ = dh.Ips.Set(p.dhcpLayer.YourClientIP, *subnet)
			//_ = dh.SubnetMask.SetAddr(dst.Options.SubnetMask)

			for range Only.Once {
				if (src.Options.MessageType == "") && (dst.Options.MessageType == "Offer") {
					src.IsDhcpServer = true
					dst.IsDhcpServer = false
					break
				}
				if (src.Options.MessageType == "Offer") && (dst.Options.MessageType == "") {
					src.IsDhcpServer = false
					dst.IsDhcpServer = true
					break
				}
				if p.dhcpLayer.Operation.String() == "Request" {
					src.IsDhcpServer = false
					dst.IsDhcpServer = false
					break
				}
				if p.dhcpLayer.Operation.String() == "Reply" {
					src.IsDhcpServer = true
					dst.IsDhcpServer = false
					break
				}
			}
			if dh.Options.Hostname != "" {
				dh.HostName = dh.Options.Hostname
			}
			dh.Options = *p.dhcpOptions

			//printPacketDHCP(*dhcp)

			fmt.Printf("\n# DHCP: %s - %s - %s - %s - %s - %s - %d\n",
				p.dhcpLayer.Operation,
				src.Options.MessageType,
				getString(p.dhcpLayer.ClientHWAddr),
				p.dhcpLayer.YourClientIP.String(),
				p.dhcpLayer.ClientIP.String(),
				getString(p.dhcpLayer.ServerName),
				p.dhcpLayer.Secs,
			)
			err = i.FoundHosts.Add(*dh)
			if err != nil {
				break
			}
		}

		// {"IsDhcpServer":false,"mac":"da:dc:6f:6a:65:75","ip":"0.0.0.0","subnet":"","options":{"Hostname":"","MeritDumpFile":"","DomainName":"","RootPath":"","ExtensionsPath":"","NISDomain":"","NetBIOSTCPScope":"","XFontServer":"","XDisplayManager":"","Message":"","DomainSearch":null,"MessageType":"","SubnetMask":"","ServerID":"","BroadcastAddr":"","SolicitAddr":"","RequestIP":"","Timer1":0,"Timer2":0,"LeaseTime":0,"PathMTUAgingTimeout":0,"ARPTimeout":0,"TCPKeepAliveInt":0,"ParamsRequest":""},"hostname":""}
		// {"IsDhcpServer":false,"mac":"da:dc:6f:6a:65:75","ip":"0.0.0.0","subnet":"","options":{"Hostname":"MickiPhone","MeritDumpFile":"","DomainName":"","RootPath":"","ExtensionsPath":"","NISDomain":"","NetBIOSTCPScope":"","XFontServer":"","XDisplayManager":"","Message":"","DomainSearch":null,"MessageType":"Request","SubnetMask":"","ServerID":"","BroadcastAddr":"","SolicitAddr":"","RequestIP":"","Timer1":0,"Timer2":0,"LeaseTime":0,"PathMTUAgingTimeout":0,"ARPTimeout":0,"TCPKeepAliveInt":0,"ParamsRequest":"\u0001y\u0003\u0006\u000frw\ufffd"},"hostname":""}

		//dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
		//if dhcpLayer != nil {
		//	//var dhcp *layers.DHCPv4
		//	dhcp, ok := dhcpLayer.(*layers.DHCPv4)
		//	if !ok {
		//		err = errors.New("not a layers.DHCPv4 structure")
		//		break
		//	}
		//
		//	dst.Options = *GetDhcpOptions(dhcp.Options)
		//
		//	if dst.Mac.NotEquals(dhcp.ClientHWAddr) {
		//		fmt.Printf("%s != %s\n", dst.Mac, dhcp.ClientHWAddr)
		//	}
		//	if dst.Ip.NotEquals(dhcp.YourClientIP) {
		//		fmt.Printf("%s != %s\n", dst.Mac, dhcp.ClientHWAddr)
		//	}
		//	//if dst.SubnetMask.NotEquals(dst.Options.SubnetMask) {
		//	//	fmt.Printf("%v != %v\n", dst.SubnetMask, dst.Options.SubnetMask)
		//	//}
		//
		//	_ = dst.Mac.Set(dhcp.ClientHWAddr)
		//	_ = dst.Ip.SetString(dhcp.YourClientIP.String() + "/" + dst.Options.SubnetMask.String() )
		//	//_ = dst.SubnetMask.SetAddr(dst.Options.SubnetMask)
		//
		//	fmt.Printf("DHCP: %s - %s - %s - %s - %s - %s - %d\n",
		//		dhcp.Operation,
		//		src.Options.MessageType,
		//		getString(dhcp.ClientHWAddr),
		//		dhcp.YourClientIP.String(),
		//		dhcp.ClientIP.String(),
		//		getString(dhcp.ServerName),
		//		dhcp.Secs,
		//	)
		//
		//	for range Only.Once {
		//		if (src.Options.MessageType == "") && (dst.Options.MessageType == "Offer") {
		//			src.IsDhcpServer = true
		//			dst.IsDhcpServer = false
		//			break
		//		}
		//		if (src.Options.MessageType == "Offer") && (dst.Options.MessageType == "") {
		//			src.IsDhcpServer = false
		//			dst.IsDhcpServer = true
		//			break
		//		}
		//		if dhcp.Operation.String() == "Request" {
		//			src.IsDhcpServer = false
		//			dst.IsDhcpServer = true
		//			break
		//		}
		//		if dhcp.Operation.String() == "Reply" {
		//			src.IsDhcpServer = true
		//			dst.IsDhcpServer = false
		//			break
		//		}
		//	}
		//	if src.Options.Hostname != "" {
		//		src.HostName = src.Options.Hostname
		//	}
		//	if dst.Options.Hostname != "" {
		//		dst.HostName = dst.Options.Hostname
		//	}
		//
		//	//printPacketDHCP(*dhcp)
		//	//src.Str = src.Options.String()
		//	//dst.Str = dst.Options.String()
		//}
		//
		//ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
		//if ethernetLayer != nil {
		//	ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		//	_ = src.Mac.Set(ethernetPacket.SrcMAC)
		//	_ = dst.Mac.Set(ethernetPacket.DstMAC)
		//	fmt.Printf("# From MAC %s to %s\n", ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
		//}
		//
		//ipLayer := packet.Layer(layers.LayerTypeIPv4)
		//if ipLayer != nil {
		//	ip, _ := ipLayer.(*layers.IPv4)
		//	_ = src.Ip.SetAddr(ip.SrcIP)
		//	_ = dst.Ip.SetAddr(ip.DstIP)
		//	fmt.Printf("# From IP %s to %s\n", ip.SrcIP, ip.DstIP)
		//}
		//
		//arpLayer := packet.Layer(layers.LayerTypeARP)
		//if arpLayer != nil {
		//	arp, _ := arpLayer.(*layers.ARP)
		//	printPacketArp(*arp)
		//}
		//
		//fmt.Print("All packet layers: ")
		//for _, layer := range packet.Layers() {
		//	fmt.Printf("%s\t", layer.LayerType())
		//}
		//fmt.Println()
		//
		//applicationLayer := packet.ApplicationLayer()
		//if applicationLayer != nil {
		//	fmt.Println("Application layer/Payload found.")
		//	fmt.Printf("%s\n", applicationLayer.Payload())
		//
		//	//// Search for a string inside the payload
		//	//if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
		//	//	fmt.Println("HTTP found!")
		//	//}
		//}
		//
		//// Check for errors
		//if err2 := packet.ErrorLayer(); err2 != nil {
		//	err = errors.New(fmt.Sprintf("Decode Error: ", err2))
		//}
		//
		//// {"IsDhcpServer":false,"mac":"da:dc:6f:6a:65:75","ip":"0.0.0.0","subnet":"","options":{"Hostname":"","MeritDumpFile":"","DomainName":"","RootPath":"","ExtensionsPath":"","NISDomain":"","NetBIOSTCPScope":"","XFontServer":"","XDisplayManager":"","Message":"","DomainSearch":null,"MessageType":"","SubnetMask":"","ServerID":"","BroadcastAddr":"","SolicitAddr":"","RequestIP":"","Timer1":0,"Timer2":0,"LeaseTime":0,"PathMTUAgingTimeout":0,"ARPTimeout":0,"TCPKeepAliveInt":0,"ParamsRequest":""},"hostname":""}
		//// {"IsDhcpServer":false,"mac":"da:dc:6f:6a:65:75","ip":"0.0.0.0","subnet":"","options":{"Hostname":"MickiPhone","MeritDumpFile":"","DomainName":"","RootPath":"","ExtensionsPath":"","NISDomain":"","NetBIOSTCPScope":"","XFontServer":"","XDisplayManager":"","Message":"","DomainSearch":null,"MessageType":"Request","SubnetMask":"","ServerID":"","BroadcastAddr":"","SolicitAddr":"","RequestIP":"","Timer1":0,"Timer2":0,"LeaseTime":0,"PathMTUAgingTimeout":0,"ARPTimeout":0,"TCPKeepAliveInt":0,"ParamsRequest":"\u0001y\u0003\u0006\u000frw\ufffd"},"hostname":""}

		fmt.Printf("\n# SRC\n")
		err = i.FoundHosts.Add(*src)
		if err != nil {
			break
		}

		//if dst.Mac.Equals(broadcastMAC) {
		//	break
		//}

		fmt.Printf("\n# DST\n")
		err = i.FoundHosts.Add(*dst)
		if err != nil {
			break
		}

		fmt.Println("################################################################################")
	}

	return err
}

func (i *Interface) AddHost(host Host) error {
	return i.FoundHosts.Add(host)
}

//func (d *Interface) ParsePacket(packet gopacket.Packet) error {
//	var err error
//
//	for range Only.Once {
//		var src Host
//		var dst Host
//
//		if d.Hosts == nil {
//			d.Hosts = make(Hosts)
//		}
//
//		dhcpLayer := packet.Layer(layers.LayerTypeDHCPv4)
//		var dhcp *layers.DHCPv4
//		if dhcpLayer != nil {
//			dhcp, _ = dhcpLayer.(*layers.DHCPv4)
//			dst.Options = *GetDhcpOptions(dhcp.Options)
//
//			if dst.Mac != dhcp.ClientHWAddr.String() {
//				fmt.Printf("%s != %s\n", dst.Mac, dhcp.ClientHWAddr.String())
//			}
//			if dst.Ip.String() != dhcp.YourClientIP.String() {
//				fmt.Printf("%s != %s\n", dst.Mac, dhcp.ClientHWAddr.String())
//			}
//			if dst.SubnetMask.String() != dst.Options.SubnetMask.String() {
//				fmt.Printf("%s != %s\n", dst.SubnetMask.String(), dst.Options.SubnetMask.String())
//			}
//
//			dst.Mac = dhcp.ClientHWAddr.String()
//			dst.Ip = dhcp.YourClientIP
//			dst.SubnetMask = dst.Options.SubnetMask
//			fmt.Printf("DHCP: %s	-	%s	%s	%s	%s\n",
//				dhcp.Operation,
//				dhcp.ClientHWAddr.String(),
//				dhcp.YourClientIP.String(),
//				dhcp.ServerName,
//				dhcp.ClientIP.String(),
//			)
//			printPacketDHCP(*dhcp)
//			//fmt.Printf("DHCPv4: %s => %s\n%s\n",
//			//	dhcp.ClientHWAddr.String(),
//			//	dhcp.YourClientIP.String(),
//			//	GetDhcpOptions(dhcp.Options).String(),
//			//)
//		}
//
//		// 	layer := pack.Layer(layers.LayerTypeDHCPv4)
//		// Let's see if the packet is an ethernet packet
//		ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
//		if ethernetLayer != nil {
//			//fmt.Println("Ethernet layer detected.")
//			ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
//			//fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
//			//fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
//			// Ethernet type is typically IPv4 but could be ARP or other
//			//fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
//			//fmt.Println()
//
//			src.Mac = ethernetPacket.SrcMAC.String()
//			dst.Mac = ethernetPacket.DstMAC.String()
//			//fmt.Printf("LayerTypeEthernet: %s => %s\n",
//			//	ethernetPacket.SrcMAC.String(),
//			//	ethernetPacket.DstMAC.String(),
//			//)
//		}
//
//		// Let's see if the packet is IP (even though the ether type told us)
//		ipLayer := packet.Layer(layers.LayerTypeIPv4)
//		if ipLayer != nil {
//			//fmt.Println("IPv4 layer detected.")
//			ip, _ := ipLayer.(*layers.IPv4)
//
//			fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
//			src.Ip = ip.SrcIP
//			dst.Ip = ip.DstIP
//			//fmt.Printf("LayerTypeIPv4: %s\n",
//			//	ip.SrcIP.String(),
//			//)
//		}
//
//		//// Let's see if the packet is TCP
//		//tcpLayer := packet.Layer(layers.LayerTypeTCP)
//		//if tcpLayer != nil {
//		//	fmt.Println("TCP layer detected.")
//		//	tcp, _ := tcpLayer.(*layers.TCP)
//		//
//		//	// TCP layer variables:
//		//	// SrcPort, DstPort, Seq, Ack, DataOffset, Window, Checksum, Urgent
//		//	// Bool flags: FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
//		//	fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
//		//	fmt.Println("Sequence number: ", tcp.Seq)
//		//	fmt.Println()
//		//	//ret.Tcp = tcp.Options
//		//}
//
//		arpLayer := packet.Layer(layers.LayerTypeARP)
//		if arpLayer != nil {
//			arp, _ := arpLayer.(*layers.ARP)
//			printPacketArp(*arp)
//		}
//
//		// Iterate over all layers, printing out each layer type
//		fmt.Print("All packet layers: ")
//		for _, layer := range packet.Layers() {
//			fmt.Printf("%s\t", layer.LayerType())
//			//fmt.Printf("%s\n", spew.Sdump(layer))
//			////layer.LayerType().Contains()
//			//if dhcpLayer, ok := layer.(*layers.DHCPv4); ok {
//			//	//printPacketDHCP(*dhcpLayer)
//			//	fmt.Printf("DHCPv4: %s => %s\n\t%s\n",
//			//		dhcpLayer.ClientHWAddr.String(),
//			//		dhcpLayer.YourClientIP.String(),
//			//		dhcpLayer.Options.String(),
//			//		)
//			//}
//		}
//		fmt.Println()
//
//		// When iterating through packet.Layers() above,
//		// if it lists Payload layer then that is the same as
//		// this applicationLayer. applicationLayer contains the payload
//		applicationLayer := packet.ApplicationLayer()
//		if applicationLayer != nil {
//			fmt.Println("Application layer/Payload found.")
//			fmt.Printf("%s\n", applicationLayer.Payload())
//
//			// Search for a string inside the payload
//			if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
//				fmt.Println("HTTP found!")
//			}
//		}
//
//		// Check for errors
//		if err := packet.ErrorLayer(); err != nil {
//			fmt.Println("Error decoding some part of the packet:", err)
//		}
//
//		for range Only.Once {
//			if (src.Options.MessageType == "") && (dst.Options.MessageType == "Offer") {
//				src.IsDhcpServer = true
//				dst.IsDhcpServer = false
//				break
//			}
//			if (src.Options.MessageType == "Offer") && (dst.Options.MessageType == "") {
//				src.IsDhcpServer = false
//				dst.IsDhcpServer = true
//				break
//			}
//			if dhcp.Operation.String() == "Request" {
//				src.IsDhcpServer = false
//				dst.IsDhcpServer = true
//				break
//			}
//		}
//		src.HostName = src.Options.Hostname
//		dst.HostName = dst.Options.Hostname
//
//		d.Hosts[src.Mac] = src
//		d.Hosts[dst.Mac] = dst
//
//		// {"IsDhcpServer":false,"mac":"da:dc:6f:6a:65:75","ip":"0.0.0.0","subnet":"","options":{"Hostname":"","MeritDumpFile":"","DomainName":"","RootPath":"","ExtensionsPath":"","NISDomain":"","NetBIOSTCPScope":"","XFontServer":"","XDisplayManager":"","Message":"","DomainSearch":null,"MessageType":"","SubnetMask":"","ServerID":"","BroadcastAddr":"","SolicitAddr":"","RequestIP":"","Timer1":0,"Timer2":0,"LeaseTime":0,"PathMTUAgingTimeout":0,"ARPTimeout":0,"TCPKeepAliveInt":0,"ParamsRequest":""},"hostname":""}
//		// {"IsDhcpServer":false,"mac":"da:dc:6f:6a:65:75","ip":"0.0.0.0","subnet":"","options":{"Hostname":"MickiPhone","MeritDumpFile":"","DomainName":"","RootPath":"","ExtensionsPath":"","NISDomain":"","NetBIOSTCPScope":"","XFontServer":"","XDisplayManager":"","Message":"","DomainSearch":null,"MessageType":"Request","SubnetMask":"","ServerID":"","BroadcastAddr":"","SolicitAddr":"","RequestIP":"","Timer1":0,"Timer2":0,"LeaseTime":0,"PathMTUAgingTimeout":0,"ARPTimeout":0,"TCPKeepAliveInt":0,"ParamsRequest":"\u0001y\u0003\u0006\u000frw\ufffd"},"hostname":""}
//
//		src.Print()
//		dst.Print()
//
//		//j, err = json.Marshal(ethernetLayer)
//		//fmt.Printf("ethernetLayer JSON:\n%s\n", j)
//		//j, err = json.Marshal(ipLayer)
//		//fmt.Printf("ipLayer JSON:\n%s\n", j)
//		//j, err = json.Marshal(dhcpLayer)
//		//fmt.Printf("dhcpLayer JSON:\n%s\n", j)
//		//j, err = json.Marshal(arpLayer)
//		//fmt.Printf("arpLayer JSON:\n%s\n", j)
//		//j, err = json.Marshal(applicationLayer)
//		//fmt.Printf("applicationLayer JSON:\n%s\n", j)
//	}
//
//	return err
//}

func (i *Interface) Print() error {
	var err error

	for range Only.Once {
		for _, host := range i.FoundHosts.Current {
			err = host.Print()
			if err != nil {
				continue
			}
		}
	}

	return err
}

//type Device struct {
//	Ethernet string	`json:"ethernet"`
//	IPv4 net.IPAddr	`json:"ipv4"`
//	Tcp DeviceTcp	`json:"tcp"`
//	Dhcp DeviceDhcp	`json:"dhcp"`
//}
//type DeviceEthernet struct {
//	*net.HardwareAddr	`json:"mac"`
//}
//type DeviceIPv4 struct {
//	net.IPAddr	`json:"ipv4"`
//}
//type DeviceTcp struct {
//
//}
//type DeviceDhcp struct {
//	Client Host	`json:"client"`
//	Server Host	`json:"server"`
//}
