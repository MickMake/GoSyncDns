package cmd

import (
	"GoSyncDNS/Only"
	"fmt"
	"github.com/spf13/cobra"
)

func InitCommands() error {
	var err error

	for range Only.Once {
		rootCmd.AddCommand(cmdConfig, cmdHelpFlags, cmdList, cmdLookup, cmdAdd, cmdRemove, cmdDel, cmdScan)
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
