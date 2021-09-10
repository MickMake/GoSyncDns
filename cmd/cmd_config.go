package cmd

import (
	"GoSyncDNS/Only"
	"fmt"
	"github.com/spf13/cobra"
	"os"
)

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
