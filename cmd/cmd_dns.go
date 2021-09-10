package cmd

import (
	"GoSyncDNS/Only"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
)

// ******************************************************************************** //
var cmdLookup = &cobra.Command{
	Use:                   "query",
	Aliases:               []string{"lookup", "search"},
	Short:                 fmt.Sprintf("Query hostname"),
	Long:                  fmt.Sprintf("Query hostname "),
	Example:               fmt.Sprintf("%s query google.com", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdLookupFunc,
	Args:                  cobra.RangeArgs(0, 2),
}

//goland:noinspection GoUnusedParameter
func cmdLookupFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		Cmd.Error = Cmd.ProcessArgs(rootCmd, args)
		if Cmd.Error != nil {
			break
		}

		args = fillArray(2, args)
		h := DNS.Query(args[0], args[1])
		if h.Error != nil {
			Cmd.Error = h.Error
			break
		}
		fmt.Printf("%v\n", h)

		if h.NoIp() {
			break
		}

		h2 := DNS.Query(h.GetIpAddr().String(), args[1])
		if h.Error != nil {
			Cmd.Error = h.Error
			break
		}
		fmt.Printf("%v\n", h2)

	}
}

// ******************************************************************************** //
var cmdList = &cobra.Command{
	Use:                   "list [zone]",
	Aliases:               []string{"dump"},
	Short:                 fmt.Sprintf("List all DNS entries in zone."),
	Long:                  fmt.Sprintf("List all DNS entries in zone. "),
	Example:               fmt.Sprintf("%s list", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdListFunc,
	Args:                  cobra.RangeArgs(0, 1),
}

//goland:noinspection GoUnusedParameter
func cmdListFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		Cmd.Error = Cmd.ProcessArgs(rootCmd, args)
		if Cmd.Error != nil {
			break
		}

		args = fillArray(1, args)
		Cmd.Error = DNS.List(args[0])
		if Cmd.Error != nil {
			break
		}
	}
}

// ******************************************************************************** //
var cmdRemove = &cobra.Command{
	Use:                   "remove <hostname> [ip address] ...",
	Aliases:               []string{},
	Short:                 fmt.Sprintf("Remove host (ANY)"),
	Long:                  fmt.Sprintf("Remove host (ANY)"),
	Example:               fmt.Sprintf("%s remove zaphod.homenet", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdRemoveFunc,
	Args:                  cobra.MinimumNArgs(1),
}

//goland:noinspection GoUnusedParameter
func cmdRemoveFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		Cmd.Error = Cmd.ProcessArgs(cmd, args)
		if Cmd.Error != nil {
			break
		}

		args = fillArray(1, args)
		Cmd.Error = DNS.DeleteAll(args[0])
		if Cmd.Error != nil {
			break
		}
	}
}

// ******************************************************************************** //
var cmdDel = &cobra.Command{
	Use:                   "del <hostname> <ip address> ...",
	Aliases:               []string{},
	Short:                 fmt.Sprintf("Delete host"),
	Long:                  fmt.Sprintf("Delete host to DNS"),
	Example:               fmt.Sprintf("%s del 10.0.1.42 zaphod.homenet", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdDelFunc,
	Args:                  cobra.MinimumNArgs(1),
}

//goland:noinspection GoUnusedParameter
func cmdDelFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		switch len(args) {
		case 0:
			_ = cmd.Help()
		case 1:
			Cmd.Error = errors.New("need IP addresses")
		default:
			Cmd.Error = Cmd.ProcessArgs(cmd, args)
			if Cmd.Error != nil {
				break
			}

			args = fillArray(2, args)
			Cmd.Error = DNS.Del("", args[0], args[1])
			if Cmd.Error != nil {
				break
			}
		}
	}
}

// ******************************************************************************** //
var cmdAdd = &cobra.Command{
	Use:                   "add <hostname> <ip address> ...",
	Aliases:               []string{},
	Short:                 fmt.Sprintf("Add host"),
	Long:                  fmt.Sprintf("Add host to DNS"),
	Example:               fmt.Sprintf("%s add zaphod.homenet 10.0.1.42", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdAddFunc,
	Args:                  cobra.MinimumNArgs(1),
}

//goland:noinspection GoUnusedParameter
func cmdAddFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		switch len(args) {
		case 0:
			_ = cmd.Help()
		case 1:
			Cmd.Error = errors.New("need IP addresses")
		default:
			Cmd.Error = Cmd.ProcessArgs(cmd, args)
			if Cmd.Error != nil {
				break
			}

			args = fillArray(2, args)
			Cmd.Error = DNS.Add("0", args[0], args[1])
			if Cmd.Error != nil {
				break
			}
		}
	}
}
