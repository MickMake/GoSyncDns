package cmd

import (
	"GoSyncDNS/Only"
	"GoSyncDNS/host"
	"GoSyncDNS/syncMdns"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/grandcat/zeroconf"
	"github.com/spf13/cobra"
	"regexp"
)

// ******************************************************************************** //
var cmdScan = &cobra.Command{
	Use:                   "scan",
	Aliases:               []string{},
	Short:                 fmt.Sprintf("Scan MDNS."),
	Long:                  fmt.Sprintf("Scan MDNS."),
	Example:               fmt.Sprintf("%s scan", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdScanFunc,
	//Args:                  cobra.MinimumNArgs(1),
}

//goland:noinspection GoUnusedParameter
func cmdScanFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		Cmd.Error = cmd.Help()

		//Cmd.Error = Cmd.ProcessArgs(cmd, args)
		//domain := DNS.FindDomain("127.0.0.1")
		//fmt.Printf("Domain: %s\n", domain)
	}
}

// ******************************************************************************** //
var cmdScanPrint = &cobra.Command{
	Use:                   "print <wait> [service name]",
	Aliases:               []string{"show"},
	Short:                 fmt.Sprintf("Scan MDNS and show hosts."),
	Long:                  fmt.Sprintf("Scan MDNS and show hosts."),
	Example:               fmt.Sprintf("%s scan print", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdScanPrintFunc,
	Args:                  cobra.MinimumNArgs(1),
}

//goland:noinspection GoUnusedParameter
func cmdScanPrintFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		Cmd.Error = Cmd.ProcessArgs(cmd, args)
		if Cmd.Error != nil {
			break
		}

		fmt.Println("Printing MDNS results...")
		args = fillArray(2, args)
		Cmd.Error = MDNS.Scan(args[0], args[1], syncMdns.PrintEntry)
		if Cmd.Error != nil {
			break
		}
	}
}

// ******************************************************************************** //
var cmdScanUpdate = &cobra.Command{
	Use:                   "update <wait> [service name]",
	Aliases:               []string{"sync"},
	Short:                 fmt.Sprintf("Scan MDNS and update DNS."),
	Long:                  fmt.Sprintf("Scan MDNS and update DNS."),
	Example:               fmt.Sprintf("%s scan update 0", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdScanUpdateFunc,
	Args:                  cobra.MinimumNArgs(1),
}

//goland:noinspection GoUnusedParameter
func cmdScanUpdateFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		Cmd.Error = Cmd.ProcessArgs(cmd, args)
		if Cmd.Error != nil {
			break
		}

		fmt.Println("Syncing MDNS with DNS...")
		args = fillArray(2, args)
		Cmd.Error = MDNS.Scan(args[0], args[1], AddToDNS)
		if Cmd.Error != nil {
			break
		}
	}
}

//var Hosts host.Hosts

func AddToDNS(m *syncMdns.MDNS, entry *zeroconf.ServiceEntry) error {
	for range Only.Once {
		//spew.Dump(entry)
		h := host.New()

		reg := regexp.MustCompile(`^(\w+:\w+:\w+:\w+:\w+:\w+).*`)
		mac := entry.ServiceInstanceName()
		mac = reg.ReplaceAllString(mac, "$1")

		h.Error = h.SetHostName(entry.HostName)
		if h.Error != nil {
			break
		}

		h.Port = entry.Port

		h.Error = h.SetText(entry.Text...)
		//if h.Error != nil {
		//	break
		//}

		h.TTL = entry.TTL

		var ip4 string
		if len(entry.AddrIPv4) > 0 {
			ip4 = entry.AddrIPv4[0].String()
		}
		h.Error = h.SetIpAddr(ip4)
		//if h.Error != nil {
		//	break
		//}

		var ip6 string
		if len(entry.AddrIPv6) > 0 {
			ip6 = entry.AddrIPv6[0].String()
		}
		h.Error = h.SetIpv6Addr(ip6)
		//if h.Error != nil {
		//	break
		//}

		h.Error = h.SetInstance(entry.Instance)
		//if h.Error != nil {
		//	break
		//}

		h.Error = h.SetService(entry.Service)
		//if h.Error != nil {
		//	break
		//}

		h.Error = h.SetMac(mac)
		//if h.Error != nil {
		//	break
		//}

		//Hosts = append(Hosts, h)
		if m.Debug {
			fmt.Printf("\n########################################\n")
			spew.Dump(h)
			fmt.Printf("########################################\n")
		}

		m.Error = DNS.SyncHosts(*h)
		if m.Error != nil {
			break
		}
	}

	return m.Error
}
