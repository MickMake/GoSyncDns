package cmd

import (
	"GoSyncDNS/Only"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

func InitCommands() error {
	var err error

	for range Only.Once {
		rootCmd.AddCommand(cmdConfig, cmdHelpFlags, cmdLookup, cmdAdd, cmdDel, cmdScan)
		cmdScan.AddCommand(cmdScanPrint, cmdScanUpdate)
		cmdConfig.AddCommand(cmdConfigWrite, cmdConfigRead)

		//foo := rootCmd.HelpTemplate()
		//foo := rootCmd.UsageTemplate()
		//foo := rootCmd.VersionTemplate()
		//fmt.Println(foo)

		rootCmd.SetHelpTemplate(DefaultHelpTemplate)
		rootCmd.SetUsageTemplate(DefaultUsageTemplate)
		rootCmd.SetVersionTemplate(DefaultVersionTemplate)

		foo := rootCmd.Commands()
		foo[0].CommandPath()
	}

	return err
}

// ******************************************************************************** //
var cmdHelpFlags = &cobra.Command{
	Use:                   "help-flags",
	Aliases:               []string{"flags"},
	Short:                 fmt.Sprintf("Help on flags"),
	Long:                  fmt.Sprintf("Help on flags"),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdHelpFlagsFunc,
	Args:                  cobra.RangeArgs(0, 0),
}

//goland:noinspection GoUnusedParameter
func cmdHelpFlagsFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		if len(args) > 0 {
			fmt.Println("Unknown sub-command.")
		}
		cmd.SetUsageTemplate(DefaultFlagHelpTemplate)
		_ = cmd.Help()
	}
}

// ******************************************************************************** //
var cmdConfig = &cobra.Command{
	Use:                   "config",
	Short:                 "List, Create, Update config file.",
	Long:                  "List, Create, Update config file.",
	Example:               fmt.Sprintf("%s config write", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdConfigFunc,
	Args:                  cobra.RangeArgs(0, 1),
}

//goland:noinspection GoUnusedParameter
func cmdConfigFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		Cmd.Error = Cmd.ProcessArgs(rootCmd, args)
		if Cmd.Error != nil {
			break
		}

		_, _ = fmt.Fprintf(os.Stderr, "Using config file '%s'\n", rootViper.ConfigFileUsed())
		if len(args) == 0 {
			_ = cmd.Help()
		}
	}
}

// ******************************************************************************** //
var cmdConfigWrite = &cobra.Command{
	Use:                   "write",
	Short:                 "Update config file.",
	Long:                  "Update config file from CLI args.",
	Example:               fmt.Sprintf("%s config write", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdConfigWriteFunc,
	Args:                  cobra.RangeArgs(0, 1),
}

//goland:noinspection GoUnusedParameter
func cmdConfigWriteFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		Cmd.Error = Cmd.ProcessArgs(rootCmd, args)
		if Cmd.Error != nil {
			break
		}

		if len(args) == 1 {
			Cmd.ConfigFile = args[0]
			rootViper.SetConfigFile(Cmd.ConfigFile)
		}

		_, _ = fmt.Fprintf(os.Stderr, "Using config file '%s'\n", rootViper.ConfigFileUsed())
		Cmd.Error = openConfig()
		if Cmd.Error != nil {
			break
		}

		Cmd.Error = writeConfig()
		if Cmd.Error != nil {
			break
		}

	}
}

// ******************************************************************************** //
var cmdConfigRead = &cobra.Command{
	Use:                   "read",
	Short:                 "Read config file.",
	Long:                  "Read config file.",
	Example:               fmt.Sprintf("%s config read", DefaultBinaryName),
	DisableFlagParsing:    false,
	DisableFlagsInUseLine: false,
	Run:                   cmdConfigReadFunc,
	Args:                  cobra.RangeArgs(0, 1),
}

//goland:noinspection GoUnusedParameter
func cmdConfigReadFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		Cmd.Error = Cmd.ProcessArgs(rootCmd, args)
		if Cmd.Error != nil {
			break
		}

		if len(args) == 1 {
			Cmd.ConfigFile = args[0]
			rootViper.SetConfigFile(Cmd.ConfigFile)
		}

		_, _ = fmt.Fprintf(os.Stderr, "Using config file '%s'\n", rootViper.ConfigFileUsed())
		Cmd.Error = openConfig()
		if Cmd.Error != nil {
			break
		}

		Cmd.Error = readConfig()
		if Cmd.Error != nil {
			break
		}

	}
}

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
	Args:                  cobra.RangeArgs(0, 1),
}

//goland:noinspection GoUnusedParameter
func cmdLookupFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		Cmd.Error = Cmd.ProcessArgs(rootCmd, args)
		if Cmd.Error != nil {
			break
		}

		args = fillArray(1, args)
		Cmd.Error = DNS.SearchMx(args[0])
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
			Cmd.Error = DNS.Del(0, args[0], args[1:]...)
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
			Cmd.Error = DNS.Add(0, args[0], args[1:]...)
			if Cmd.Error != nil {
				break
			}
		}
	}
}
