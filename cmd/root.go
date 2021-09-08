package cmd

import (
	"GoSyncDNS/Only"
	"GoSyncDNS/syncDns"
	"GoSyncDNS/syncMdns"
	"fmt"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"os"
	"path/filepath"
	"strings"
)

var DNS *syncDns.DNS
var MDNS *syncMdns.MDNS
var Cmd CommandArgs
var rootViper *viper.Viper

var rootCmd = &cobra.Command{
	Use:              DefaultBinaryName,
	Short:            fmt.Sprintf("%s - MDNS to DNS sync tool.", DefaultBinaryName),
	Long:             fmt.Sprintf("%s - MDNS to DNS sync tool.", DefaultBinaryName),
	Run:              gbRootFunc,
	TraverseChildren: true,
	PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
		// You can bind cobra and viper in a few locations, but PersistencePreRunE on the root command works well
		return initConfig(cmd)
	},
}

func init() {
	for range Only.Once {
		Cmd.ConfigDir, Cmd.Error = os.UserHomeDir()
		if Cmd.Error != nil {
			break
		}
		Cmd.ConfigDir = filepath.Join(Cmd.ConfigDir, "."+DefaultBinaryName)

		_, Cmd.Error = os.Stat(Cmd.ConfigDir)
		if os.IsExist(Cmd.Error) {
			break
		}

		Cmd.Error = os.MkdirAll(Cmd.ConfigDir, 0700)
		if Cmd.Error != nil {
			break
		}

		Cmd.ConfigFile = filepath.Join(Cmd.ConfigDir, defaultConfigFile)

		rootCmd.PersistentFlags().StringVar(&Cmd.ConfigFile, flagConfigFile, Cmd.ConfigFile, fmt.Sprintf("%s: config file.", DefaultBinaryName))
		//_ = rootCmd.PersistentFlags().MarkHidden(flagConfigFile)

		//rootCmd.PersistentFlags().StringVarP(&Cmd.Username, flagUsername, "u", "", fmt.Sprintf("Set PBX extension username."))
		//rootCmd.PersistentFlags().StringVarP(&Cmd.Password, flagPassword, "p", "", fmt.Sprintf("Set PBX extension password."))
		//rootCmd.PersistentFlags().StringVarP(&Cmd.ClientId, flagClientId, "i", "", fmt.Sprintf("Set PBX API client id."))
		//rootCmd.PersistentFlags().StringVarP(&Cmd.ClientSecret, flagClientSecret, "s", "", fmt.Sprintf("Set PBX API client secret."))
		rootCmd.PersistentFlags().StringVarP(&Cmd.Domain, flagDomain, "d", defaultDomain, fmt.Sprintf("Set DNS domain."))

		rootCmd.PersistentFlags().StringVarP(&Cmd.Host, flagHost, "", defaultHost, fmt.Sprintf("Set provider API URL or hostname."))
		rootCmd.PersistentFlags().StringVarP(&Cmd.Port, flagPort, "", "", fmt.Sprintf("Set provider port."))
		rootCmd.PersistentFlags().DurationVarP(&Cmd.Timeout, flagTimeout, "", defaultTimeout, fmt.Sprintf("Timeout."))

		rootCmd.PersistentFlags().StringVarP(&Cmd.GoogleSheet, flagGoogleSheet, "", "", fmt.Sprintf("Set Google sheet for updates."))
		rootCmd.PersistentFlags().BoolVarP(&Cmd.GoogleSheetUpdate, flagGoogleSheetUpdate, "", false, fmt.Sprintf("Update Google sheets."))

		rootCmd.PersistentFlags().BoolVarP(&Cmd.Debug, flagDebug, "", false, fmt.Sprintf("Debug mode."))
		rootCmd.PersistentFlags().BoolVarP(&Cmd.Quiet, flagQuiet, "q", false, fmt.Sprintf("Silence all messages."))

		//rootCmd.PersistentFlags().StringVar(&Cmd.pbxTokenExpiry, flagPbxTokenExpiry, "", "DNS Token expiry")
		//_ = rootCmd.PersistentFlags().MarkHidden(flagPbxTokenExpiry)

		//cobra.OnInitialize(initConfig)
		cobra.EnableCommandSorting = false
	}
}

// initConfig reads in config file and ENV variables if set.
func initConfig(cmd *cobra.Command) error {
	var err error

	for range Only.Once {
		rootViper = viper.New()
		rootViper.AddConfigPath(Cmd.ConfigDir)
		rootViper.SetConfigFile(Cmd.ConfigFile)
		//rootViper.SetConfigName("config")

		// If a config file is found, read it in.
		err = openConfig()
		if err != nil {
			break
		}

		rootViper.SetEnvPrefix(EnvPrefix)
		rootViper.AutomaticEnv() // read in environment variables that match
		err = bindFlags(cmd, rootViper)
		if err != nil {
			break
		}
	}

	return err
}

func openConfig() error {
	var err error

	for range Only.Once {
		err = rootViper.ReadInConfig()
		if _, ok := err.(viper.UnsupportedConfigError); ok {
			break
		}

		if _, ok := err.(viper.ConfigParseError); ok {
			break
		}

		if _, ok := err.(viper.ConfigMarshalError); ok {
			break
		}

		if os.IsNotExist(err) {
			rootViper.SetDefault(flagHost, Cmd.Host)
			rootViper.SetDefault(flagPort, Cmd.Port)
			rootViper.SetDefault(flagDebug, Cmd.Debug)
			rootViper.SetDefault(flagQuiet, Cmd.Quiet)
			rootViper.SetDefault(flagTimeout, Cmd.Timeout)

			rootViper.SetDefault(flagDomain, Cmd.Domain)

			rootViper.SetDefault(flagGoogleSheet, Cmd.GoogleSheet)
			rootViper.SetDefault(flagGoogleSheetUpdate, Cmd.GoogleSheetUpdate)

			err = rootViper.WriteConfig()
			if err != nil {
				break
			}

			err = rootViper.ReadInConfig()
			break
		}
		if err != nil {
			break
		}

		err = rootViper.MergeInConfig()
		if err != nil {
			break
		}

		//err = viper.Unmarshal(Cmd)
	}

	return err
}

func writeConfig() error {
	var err error

	for range Only.Once {
		err = rootViper.MergeInConfig()
		if err != nil {
			break
		}

		rootViper.Set(flagHost, Cmd.Host)
		rootViper.Set(flagPort, Cmd.Port)
		rootViper.Set(flagDebug, Cmd.Debug)
		rootViper.Set(flagQuiet, Cmd.Quiet)
		rootViper.Set(flagTimeout, Cmd.Timeout)

		rootViper.Set(flagDomain, Cmd.Domain)

		rootViper.Set(flagGoogleSheet, Cmd.GoogleSheet)
		rootViper.Set(flagGoogleSheetUpdate, Cmd.GoogleSheetUpdate)

		err = rootViper.WriteConfig()
		if err != nil {
			break
		}
	}

	return err
}

func readConfig() error {
	var err error

	for range Only.Once {
		err = rootViper.ReadInConfig()
		if err != nil {
			break
		}

		_, _ = fmt.Fprintln(os.Stderr, "Config file settings:")

		_, _ = fmt.Fprintf(os.Stderr, "Host:	%v\n", rootViper.Get(flagHost))
		_, _ = fmt.Fprintf(os.Stderr, "Port:	%v\n", rootViper.Get(flagPort))
		_, _ = fmt.Fprintf(os.Stderr, "Domain:	%v\n", rootViper.Get(flagDomain))
		_, _ = fmt.Fprintln(os.Stderr)

		_, _ = fmt.Fprintf(os.Stderr, "Debug:	%v\n", rootViper.Get(flagDebug))
		_, _ = fmt.Fprintf(os.Stderr, "Quiet:	%v\n", rootViper.Get(flagQuiet))
		_, _ = fmt.Fprintf(os.Stderr, "Timeout:	%v\n", rootViper.Get(flagTimeout))
	}

	return err
}

func bindFlags(cmd *cobra.Command, v *viper.Viper) error {
	var err error

	cmd.Flags().VisitAll(func(f *pflag.Flag) {
		// Environment variables can't have dashes in them, so bind them to their equivalent
		// keys with underscores, e.g. --favorite-color to STING_FAVORITE_COLOR
		if strings.Contains(f.Name, "-") {
			envVarSuffix := strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
			err = v.BindEnv(f.Name, fmt.Sprintf("%s_%s", EnvPrefix, envVarSuffix))
		}

		// Apply the viper config value to the flag when the flag is not set and viper has a value
		if !f.Changed && v.IsSet(f.Name) {
			val := v.Get(f.Name)
			err = cmd.Flags().Set(f.Name, fmt.Sprintf("%v", val))
		}
	})

	return err
}

func gbRootFunc(cmd *cobra.Command, args []string) {
	for range Only.Once {
		_ = cmd.Help()
	}

}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() error {
	var err error

	for range Only.Once {
		err = InitCommands()
		if err != nil {
			break
		}

		err = rootCmd.Execute()
		if err != nil {
			break
		}

		if Cmd.Error != nil {
			err = Cmd.Error
		}
	}

	return err
}