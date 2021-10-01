package discover

import (
	"GoSyncDNS/Only"
	"bytes"
	"fmt"
	"github.com/google/gopacket/layers"
	"net"
	"strconv"
	"strings"
)

//type Hostname struct {
//	string
//	net.IP
//}
////type Hostname string
//type Hostnames []Hostname

type DhcpOptions struct {
	Hostname        string `json:"hostname,omitempty"`
	MeritDumpFile   string `json:"merit_dump_file,omitempty"`
	DomainName      string `json:"domain_name,omitempty"`
	RootPath        string `json:"root_path,omitempty"`
	ExtensionsPath  string `json:"extensions_path,omitempty"`
	NISDomain       string `json:"nis_domain,omitempty"`
	NetBIOSTCPScope string `json:"net_biostcp_scope,omitempty"`
	Message         string `json:"message,omitempty"`

	DomainSearch []string `json:"domain_search,omitempty"`

	MessageType string `json:"message_type,omitempty"`

	SubnetMask    Ip `json:"subnet_mask,omitempty"`
	BroadcastAddr Ip `json:"broadcast_addr,omitempty"`
	SolicitAddr   Ip `json:"solicit_addr,omitempty"`
	RequestIP     Ip `json:"request_ip,omitempty"`

	ServerID         Ip   `json:"server_id,omitempty"`
	XFontServer      []Ip `json:"x_font_server,omitempty"`
	XDisplayManager  []Ip `json:"x_display_manager,omitempty"`
	NameServer       []Ip `json:"name_server,omitempty"`
	DomainServer     []Ip `json:"domain_server,omitempty"`
	LogServer        []Ip `json:"log_server,omitempty"`
	QuoteServer      []Ip `json:"quote_server,omitempty"`
	LprServer        []Ip `json:"lpr_server,omitempty"`
	ImpressServer    []Ip `json:"impress_server,omitempty"`
	RlpServer        []Ip `json:"rlp_server,omitempty"`
	CookieServer     []Ip `json:"cookie_server,omitempty"`
	Router           []Ip `json:"router,omitempty"`
	NetBIOSOverTCPNS []Ip `json:"net_bios_over_tcpns,omitempty"`
	NTPServers       []Ip `json:"ntp_servers,omitempty"`
	MitLCS           []Ip `json:"mit_lcs,omitempty"`
	SwapServer       []Ip `json:"swap_server,omitempty"`

	Timer1              uint32 `json:"timer_1,omitempty"`
	Timer2              uint32 `json:"timer_2,omitempty"`
	LeaseTime           uint32 `json:"lease_time,omitempty"`
	PathMTUAgingTimeout uint32 `json:"path_mtu_aging_timeout,omitempty"`
	ARPTimeout          uint32 `json:"arp_timeout,omitempty"`
	TCPKeepAliveInt     uint32 `json:"tcp_keep_alive_int,omitempty"`

	ParamsRequest         string `json:"params_request,omitempty"`
	ClassID               string `json:"class_id,omitempty"`
	TimeOffset            uint32 `json:"time_offset,omitempty"`
	Pad                   string `json:"pad,omitempty"`
	DNS                   []Ip   `json:"dns,omitempty"`
	IPForwarding          bool   `json:"ip_forwarding,omitempty"`
	TimeServer            []Ip   `json:"time_server,omitempty"`
	ResLocServer          []Ip   `json:"res_loc_server,omitempty"`
	BootfileSize          uint32 `json:"bootfile_size,omitempty"`
	SourceRouting         bool   `json:"source_routing,omitempty"`
	PolicyFilter          string `json:"policy_filter,omitempty"`
	InterfaceMTU          uint32 `json:"interface_mtu,omitempty"`
	DefaultTTL            string `json:"default_ttl,omitempty"`
	DatagramMTU           uint32 `json:"datagram_mtu,omitempty"`
	AllSubsLocal          bool   `json:"all_subs_local,omitempty"`
	PathPlateuTableOption uint32 `json:"path_plateu_table_option,omitempty"`
	MaskDiscovery         bool   `json:"mask_discovery,omitempty"`
	RouterDiscovery       bool   `json:"router_discovery,omitempty"`
	MaskSupplier          bool   `json:"mask_supplier,omitempty"`
	StaticRoute           string `json:"static_route,omitempty"`
	ARPTrailers           bool   `json:"arp_trailers,omitempty"`
	NISServers            []Ip   `json:"nis_servers,omitempty"`
	TCPTTL                string `json:"tcpttl,omitempty"`
	EthernetEncap         bool   `json:"ethernet_encap,omitempty"`
	TCPKeepAliveGarbage   bool   `json:"tcp_keep_alive_garbage,omitempty"`
	NetBIOSTCPNS          []Ip   `json:"net_biostcpns,omitempty"`
	NetBIOSTCPDDS         []Ip   `json:"net_biostcpdds,omitempty"`
	VendorOption          string `json:"vendor_option,omitempty"`
	NETBIOSTCPNodeType    string `json:"netbiostcp_node_type,omitempty"`
	ExtOptions            string `json:"ext_options,omitempty"`
	MaxMessageSize        uint32 `json:"max_message_size,omitempty"`
	T1                    uint32 `json:"t_1,omitempty"`
	T2                    uint32 `json:"t_2,omitempty"`
	ClientID              string `json:"client_id,omitempty"`
	SIPServers            string `json:"sip_servers,omitempty"`
	End                   string `json:"end,omitempty"`
	ClasslessStaticRoute  string `json:"classless_static_route,omitempty"`

	//TimeOffset string
	//Router string
	//Rfc868 string
	//Ien116 string
	//DNS string
	//mitLCS string
	//CookieServer string
	//LPRServer string
	//ImpressServer string
	//ResourceLocationServer string
	//BootfileSize string
	//SwapServer string
	//IPForwarding string
	//SourceRouting string
	//PolicyFilter string
	//DatagramMTU string
	//DefaultTTL string
	//PathPlateuTableOption string
	//InterfaceMTU string
	//AllSubsLocal string
	//MaskDiscovery string
	//MaskSupplier string
	//RouterDiscovery string
	//StaticRoute string
	//ARPTrailers string
	//EthernetEncap string
	//TCPTTL string
	//TCPKeepAliveGarbage string
	//NISServers string
	//NTPServers string
	//VendorOption string
	//NetBIOSOverTCPNS string
	//NetBiosOverTCPDDS string
	//NetBIOSOverTCPNodeType string
	//NetBIOSOverTCPScope string
	//SipServers string
	//ExtOpts string
	//MaxDHCPSize string
	//ClassID string
	//ClientID string
	//DomainSearch string
	//ClasslessStaticRoute string
}

//func (d *DhcpOptions) GetSubnet() net.IP {
//	return d.SubnetMask.GetSubnet()
//}

func (d *DhcpOptions) GetSubnetMask() net.IPMask {
	return d.SubnetMask.GetMask()
}

func (d *DhcpOptions) GetBroadcast() net.IP {
	return d.BroadcastAddr.Get()
}

func (d *DhcpOptions) GetSolicitAddr() net.IP {
	return d.SolicitAddr.Get()
}

func (d *DhcpOptions) GetRequestIP() net.IP {
	return d.RequestIP.Get()
}

func (d *DhcpOptions) GetServerID() net.IP {
	return d.ServerID.Get()
}

type DhcpOption layers.DHCPOption

func (d *DhcpOption) GetHostname() string {
	return d.getTypeString()
}
func (d *DhcpOption) getTypeDefault() string {
	return fmt.Sprintf("%s", d.Data)
}
func (d *DhcpOption) getTypeString() string {
	return fmt.Sprintf("%s", string(d.Data))
}
func (d *DhcpOption) getTypeBool() bool {
	if string(d.Data) == "1" {
		return true
	}
	if string(d.Data) == "Y" {
		return true
	}
	return false
}
func (d *DhcpOption) getTypeStringArray() []string {
	var ret []string
	for _, s := range strings.Split(string(d.Data), "\x00") {
		if len(s) == 0 {
			continue
		}
		ret = append(ret, s[1:])
	}
	return ret
}
func (d *DhcpOption) getTypeMessage() string {
	var ret string
	if len(d.Data) != 1 {
		ret += "INVALID"
	}
	ret += fmt.Sprintf("%s", layers.DHCPMsgType(d.Data[0]))
	return ret
}
func (d *DhcpOption) getTypeIpAddr() Ip {
	var ret Ip
	if len(d.Data) < 4 {
		//ret = "INVALID"
	} else {
		_ = ret.SetAddr(d.Data)
	}
	return ret
}
func (d *DhcpOption) getTypeIpAddrs() []Ip {
	var ret []Ip
	for _, s := range strings.Split(string(d.Data), "\x00") {
		var i Ip
		err := i.SetString(s)
		if err != nil {
			continue
		}
		ret = append(ret, i)
	}
	//ret = []net.IP{net.ParseIP(string(d.Data))}
	return ret
}
func (d *DhcpOption) getTypeInteger() uint32 {
	var ret uint32
	if len(d.Data) != 4 {
		//ret = "INVALID"
	} else {
		i, _ := strconv.Atoi(fmt.Sprintf("%d",
			uint32(d.Data[0])<<24|uint32(d.Data[1])<<16|uint32(d.Data[2])<<8|uint32(d.Data[3])))
		ret = uint32(i)
	}
	return ret
}
func (d *DhcpOption) getTypeParams() string {
	var ret string
	buf := &bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("\tOption(%s:", d.Type))
	for i, v := range d.Data {
		buf.WriteString(layers.DHCPOpt(v).String())
		if i+1 != len(d.Data) {
			buf.WriteByte(',')
		}
	}
	buf.WriteString(")\n")
	ret += buf.String()
	return ret
}

func (d *DhcpOption) printTypeDefault() string {
	return fmt.Sprintf("\tOption(%s:%s)\n", d.Type, d.getTypeDefault())
}
func (d *DhcpOption) printTypeString() string {
	return fmt.Sprintf("\tOption(%s:%s)\n", d.Type, d.getTypeString())
}
func (d *DhcpOption) printTypeMessage() string {
	return fmt.Sprintf("\tOption(%s:%s)\n", d.Type, d.getTypeMessage())
}
func (d *DhcpOption) printTypeIpAddr() string {
	return fmt.Sprintf("\tOption(%s:%s)\n", d.Type, d.getTypeIpAddr())
}
func (d *DhcpOption) printTypeInteger() string {
	return fmt.Sprintf("\tOption(%s:%s)\n", d.Type, d.getTypeInteger())
}
func (d *DhcpOption) printTypeParams() string {
	var ret string
	buf := &bytes.Buffer{}
	buf.WriteString(fmt.Sprintf("\tOption(%s:", d.Type))
	for i, v := range d.Data {
		buf.WriteString(layers.DHCPOpt(v).String())
		if i+1 != len(d.Data) {
			buf.WriteByte(',')
		}
	}
	buf.WriteString(")\n")
	ret += buf.String()
	return ret
}

func (d *DhcpOptions) String() string {
	return fmt.Sprintf(`
		Hostname:            %v
		MeritDumpFile:       %v
		DomainName:          %v
		RootPath:            %v
		ExtensionsPath:      %v
		NISDomain:           %v
		NetBIOSTCPScope:     %v
		XFontServer:         %v
		XDisplayManager:     %v
		Message:             %v
		DomainSearch:        %s
		MessageType:         %v
		SubnetMask:          %v
		ServerID:            %v
		BroadcastAddr:       %v
		SolicitAddr:         %v
		RequestIP:           %v
		Timer1:                  %v
		Timer2:                  %v
		LeaseTime:           %v
		PathMTUAgingTimeout: %v
		ARPTimeout:          %v
		TCPKeepAliveInt:     %v
		ParamsRequest:       %v`,
		d.Hostname,
		d.MeritDumpFile,
		d.DomainName,
		d.RootPath,
		d.ExtensionsPath,
		d.NISDomain,
		d.NetBIOSTCPScope,
		d.XFontServer,
		d.XDisplayManager,
		d.Message,
		//strings.Join(d.DomainSearch, ", "),
		d.DomainSearch,
		d.MessageType,
		d.SubnetMask,
		d.ServerID,
		d.BroadcastAddr,
		d.SolicitAddr,
		d.RequestIP,
		d.Timer1,
		d.Timer2,
		d.LeaseTime,
		d.PathMTUAgingTimeout,
		d.ARPTimeout,
		d.TCPKeepAliveInt,
		d.ParamsRequest,
	)
}

func GetDhcpOptions(options layers.DHCPOptions) *DhcpOptions {
	var ret DhcpOptions

	for range Only.Once {
		for _, option := range options {
			if option.Data == nil {
				continue
			}
			o := DhcpOption(option)

			switch option.Type {
			case layers.DHCPOptPad: // DHCPOpt = 0
				ret.Pad = o.getTypeString()
			case layers.DHCPOptSubnetMask: // DHCPOpt = 1   // 4, net.IP
				ret.SubnetMask = o.getTypeIpAddr()
			case layers.DHCPOptTimeOffset: // DHCPOpt = 2   // 4, int32 (signed seconds from UTC)
				ret.TimeOffset = o.getTypeInteger()
			case layers.DHCPOptRouter: // DHCPOpt = 3   // n*4, [n]net.IP
				ret.Router = o.getTypeIpAddrs()
			case layers.DHCPOptTimeServer: // DHCPOpt = 4   // n*4, [n]net.IP
				ret.TimeServer = o.getTypeIpAddrs()
			case layers.DHCPOptNameServer: // DHCPOpt = 5   // n*4, [n]net.IP
				ret.NameServer = o.getTypeIpAddrs()
			case layers.DHCPOptDNS: // DHCPOpt = 6   // n*4, [n]net.IP
				ret.DNS = o.getTypeIpAddrs()
			case layers.DHCPOptLogServer: // DHCPOpt = 7   // n*4, [n]net.IP
				ret.LogServer = o.getTypeIpAddrs()
			case layers.DHCPOptCookieServer: // DHCPOpt = 8   // n*4, [n]net.IP
				ret.CookieServer = o.getTypeIpAddrs()
			case layers.DHCPOptLPRServer: // DHCPOpt = 9   // n*4, [n]net.IP
				ret.LprServer = o.getTypeIpAddrs()
			case layers.DHCPOptImpressServer: // DHCPOpt = 10  // n*4, [n]net.IP
				ret.ImpressServer = o.getTypeIpAddrs()
			case layers.DHCPOptResLocServer: // DHCPOpt = 11  // n*4, [n]net.IP
				ret.ResLocServer = o.getTypeIpAddrs()
			case layers.DHCPOptHostname: // DHCPOpt = 12  // n, string
				ret.Hostname = o.getTypeString()
			case layers.DHCPOptBootfileSize: // DHCPOpt = 13  // 2, uint16
				ret.BootfileSize = o.getTypeInteger()
			case layers.DHCPOptMeritDumpFile: // DHCPOpt = 14  // >1, string
				ret.MeritDumpFile = o.getTypeString()
			case layers.DHCPOptDomainName: // DHCPOpt = 15  // n, string
				ret.DomainName = o.getTypeString()
			case layers.DHCPOptSwapServer: // DHCPOpt = 16  // n*4, [n]net.IP
				ret.SwapServer = o.getTypeIpAddrs()
			case layers.DHCPOptRootPath: // DHCPOpt = 17  // n, string
				ret.RootPath = o.getTypeString()
			case layers.DHCPOptExtensionsPath: // DHCPOpt = 18  // n, string
				ret.ExtensionsPath = o.getTypeString()
			case layers.DHCPOptIPForwarding: // DHCPOpt = 19  // 1, bool
				ret.IPForwarding = o.getTypeBool()
			case layers.DHCPOptSourceRouting: // DHCPOpt = 20  // 1, bool
				ret.SourceRouting = o.getTypeBool()
			case layers.DHCPOptPolicyFilter: // DHCPOpt = 21  // 8*n, [n]{net.IP/net.IP}
				ret.PolicyFilter = o.getTypeString()
			case layers.DHCPOptDatagramMTU: // DHCPOpt = 22  // 2, uint16
				ret.DatagramMTU = o.getTypeInteger()
			case layers.DHCPOptDefaultTTL: // DHCPOpt = 23  // 1, byte
				ret.DefaultTTL = o.getTypeString()
			case layers.DHCPOptPathMTUAgingTimeout: // DHCPOpt = 24  // 4, uint32
				ret.PathMTUAgingTimeout = o.getTypeInteger()
			case layers.DHCPOptPathPlateuTableOption: // DHCPOpt = 25  // 2*n, []uint16
				ret.PathPlateuTableOption = o.getTypeInteger()
			case layers.DHCPOptInterfaceMTU: // DHCPOpt = 26  // 2, uint16
				ret.InterfaceMTU = o.getTypeInteger()
			case layers.DHCPOptAllSubsLocal: // DHCPOpt = 27  // 1, bool
				ret.AllSubsLocal = o.getTypeBool()
			case layers.DHCPOptBroadcastAddr: // DHCPOpt = 28  // 4, net.IP
				ret.BroadcastAddr = o.getTypeIpAddr()
			case layers.DHCPOptMaskDiscovery: // DHCPOpt = 29  // 1, bool
				ret.MaskDiscovery = o.getTypeBool()
			case layers.DHCPOptMaskSupplier: // DHCPOpt = 30  // 1, bool
				ret.MaskSupplier = o.getTypeBool()
			case layers.DHCPOptRouterDiscovery: // DHCPOpt = 31  // 1, bool
				ret.RouterDiscovery = o.getTypeBool()
			case layers.DHCPOptSolicitAddr: // DHCPOpt = 32  // 4, net.IP
				ret.SolicitAddr = o.getTypeIpAddr()
			case layers.DHCPOptStaticRoute: // DHCPOpt = 33  // n*8, [n]{net.IP/net.IP} -- note the 2nd is router not mask
				ret.StaticRoute = o.getTypeString()
			case layers.DHCPOptARPTrailers: // DHCPOpt = 34  // 1, bool
				ret.ARPTrailers = o.getTypeBool()
			case layers.DHCPOptARPTimeout: // DHCPOpt = 35  // 4, uint32
				ret.ARPTimeout = o.getTypeInteger()
			case layers.DHCPOptEthernetEncap: // DHCPOpt = 36  // 1, bool
				ret.EthernetEncap = o.getTypeBool()
			case layers.DHCPOptTCPTTL: // DHCPOpt = 37  // 1, byte
				ret.TCPTTL = o.getTypeString()
			case layers.DHCPOptTCPKeepAliveInt: // DHCPOpt = 38  // 4, uint32
				ret.TCPKeepAliveInt = o.getTypeInteger()
			case layers.DHCPOptTCPKeepAliveGarbage: // DHCPOpt = 39  // 1, bool
				ret.TCPKeepAliveGarbage = o.getTypeBool()
			case layers.DHCPOptNISDomain: // DHCPOpt = 40  // n, string
				ret.NISDomain = o.getTypeString()
			case layers.DHCPOptNISServers: // DHCPOpt = 41  // 4*n,  [n]net.IP
				ret.NISServers = o.getTypeIpAddrs()
			case layers.DHCPOptNTPServers: // DHCPOpt = 42  // 4*n, [n]net.IP
				ret.NTPServers = o.getTypeIpAddrs()
			case layers.DHCPOptVendorOption: // DHCPOpt = 43  // n, [n]byte // may be encapsulated.
				ret.VendorOption = o.getTypeString()
			case layers.DHCPOptNetBIOSTCPNS: // DHCPOpt = 44  // 4*n, [n]net.IP
				ret.NetBIOSTCPNS = o.getTypeIpAddrs()
			case layers.DHCPOptNetBIOSTCPDDS: // DHCPOpt = 45  // 4*n, [n]net.IP
				ret.NetBIOSTCPDDS = o.getTypeIpAddrs()
			case layers.DHCPOptNETBIOSTCPNodeType: // DHCPOpt = 46  // 1, magic byte
				ret.NETBIOSTCPNodeType = o.getTypeString()
			case layers.DHCPOptNetBIOSTCPScope: // DHCPOpt = 47  // n, string
				ret.NetBIOSTCPScope = o.getTypeString()
			case layers.DHCPOptXFontServer: // DHCPOpt = 48  // n, string
				ret.XFontServer = o.getTypeIpAddrs()
			case layers.DHCPOptXDisplayManager: // DHCPOpt = 49  // n, string
				ret.XDisplayManager = o.getTypeIpAddrs()
			case layers.DHCPOptRequestIP: // DHCPOpt = 50  // 4, net.IP
				ret.RequestIP = o.getTypeIpAddr()
			case layers.DHCPOptLeaseTime: // DHCPOpt = 51  // 4, uint32
				ret.LeaseTime = o.getTypeInteger()
			case layers.DHCPOptExtOptions: // DHCPOpt = 52  // 1, 1/2/3
				ret.ExtOptions = o.getTypeString()
			case layers.DHCPOptMessageType: // DHCPOpt = 53  // 1, 1-7
				ret.MessageType = o.getTypeString()
			case layers.DHCPOptServerID: // DHCPOpt = 54  // 4, net.IP
				ret.ServerID = o.getTypeIpAddr()
			case layers.DHCPOptParamsRequest: // DHCPOpt = 55  // n, []byte
				ret.ParamsRequest = o.getTypeString()
			case layers.DHCPOptMessage: // DHCPOpt = 56  // n, 3
				ret.Message = o.getTypeString()
			case layers.DHCPOptMaxMessageSize: // DHCPOpt = 57  // 2, uint16
				ret.MaxMessageSize = o.getTypeInteger()
			case layers.DHCPOptT1: // DHCPOpt = 58  // 4, uint32
				ret.T1 = o.getTypeInteger()
			case layers.DHCPOptT2: // DHCPOpt = 59  // 4, uint32
				ret.T2 = o.getTypeInteger()
			case layers.DHCPOptClassID: // DHCPOpt = 60  // n, []byte
				ret.ClassID = o.getTypeString()
			case layers.DHCPOptClientID: // DHCPOpt = 61  // n >=  2, []byte
				ret.ClientID = o.getTypeString()
			case layers.DHCPOptDomainSearch: // DHCPOpt = 119 // n, string
				ret.DomainSearch = o.getTypeStringArray()
			case layers.DHCPOptSIPServers: // DHCPOpt = 120 // n, url
				ret.SIPServers = o.getTypeString()
			case layers.DHCPOptClasslessStaticRoute: // DHCPOpt = 121 //
				ret.ClasslessStaticRoute = o.getTypeString()
			case layers.DHCPOptEnd: // DHCPOpt = 255
				ret.End = o.getTypeString()

			default:
				//ret += o.getTypeDefault()
				fmt.Printf("UNKNOWN: %v\n", o)
			}
		}
	}

	return &ret
}

//func PrintDhcpOptions(options layers.DHCPOptions) string {
//	var ret string
//
//	for range Only.Once {
//		for _, option := range options {
//			if option.Data == nil {
//				continue
//			}
//			o := DhcpOption(option)
//
//			switch option.Type {
//				case layers.DHCPOptHostname, layers.DHCPOptMeritDumpFile, layers.DHCPOptDomainName, layers.DHCPOptRootPath,
//					layers.DHCPOptExtensionsPath, layers.DHCPOptNISDomain, layers.DHCPOptNetBIOSTCPScope, layers.DHCPOptXFontServer,
//					layers.DHCPOptXDisplayManager, layers.DHCPOptMessage, layers.DHCPOptDomainSearch: // string
//					ret += o.printTypeString()
//
//				case layers.DHCPOptMessageType:
//					ret += o.printTypeMessage()
//
//				case layers.DHCPOptSubnetMask, layers.DHCPOptServerID, layers.DHCPOptBroadcastAddr,
//					layers.DHCPOptSolicitAddr, layers.DHCPOptRequestIP: // net.IP
//					ret += o.printTypeIpAddr()
//
//				case layers.DHCPOptT1, layers.DHCPOptT2, layers.DHCPOptLeaseTime, layers.DHCPOptPathMTUAgingTimeout,
//					layers.DHCPOptARPTimeout, layers.DHCPOptTCPKeepAliveInt: // uint32
//					ret += o.printTypeInteger()
//
//				case layers.DHCPOptParamsRequest:
//					ret += o.printTypeParams()
//
//				default:
//					ret += o.printTypeDefault()
//			}
//		}
//	}
//
//	return ret
//}
