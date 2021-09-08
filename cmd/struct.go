package cmd

import (
	"GoSyncDNS/Only"
	"GoSyncDNS/syncDns"
	"GoSyncDNS/syncMdns"
	"errors"
	"fmt"
	"github.com/spf13/cobra"
	"strings"
	"time"
)

//goland:noinspection SpellCheckingInspection
const (
	DefaultBinaryName = "GoSyncDNS"
	EnvPrefix         = "GO_SYNC_DNS"

	//flagPbxToken       = "token"
	//flagPbxTokenExpiry = "token-expiry"
	flagConfigFile = "config"
	flagDebug      = "debug"
	flagQuiet      = "quiet"

	flagHost    = "host"
	flagPort    = "port"
	flagTimeout = "timeout"
	flagDomain  = "domain"

	flagGoogleSheet       = "google-sheet"
	flagGoogleSheetUpdate = "update"

	defaultHost       = "localhost"
	defaultConfigFile = "config.json"
	defaultDomain     = "bonjour."

	defaultTimeout = time.Duration(time.Second * 30)
)

//goland:noinspection GoUnusedFunction
func showArgs(cmd *cobra.Command, args []string) {
	for range Only.Once {
		flargs := cmd.Flags().Args()
		if flargs != nil {
			fmt.Printf("'%s' called with '%s'\n", cmd.CommandPath(), strings.Join(flargs, " "))
			break
		}

		fmt.Printf("'%s' called with '%s'\n", cmd.CommandPath(), strings.Join(args, " "))
		break
	}

	fmt.Println("")
}

type CommandArgs struct {
	ConfigDir   string
	ConfigFile  string
	WriteConfig bool

	Args []string

	Url     string
	Host    string
	Port    string
	Quiet   bool
	Debug   bool
	Timeout time.Duration

	ClientId     string
	ClientSecret string
	Username     string
	Password     string
	Domain       string
	//pbxToken     string
	pbxTokenExpiry string

	GoogleSheet       string
	GoogleSheetUpdate bool

	Valid bool
	Error error
}

func (ca *CommandArgs) IsValid() error {
	for range Only.Once {
		if !ca.Valid {
			ca.Error = errors.New("args are not valid")
			break
		}
	}

	return ca.Error
}

//goland:noinspection GoUnusedParameter
func (ca *CommandArgs) ProcessArgs(cmd *cobra.Command, args []string) error {
	for range Only.Once {
		ca.Args = args

		DNS = syncDns.New(ca.Host, ca.Domain)
		if DNS.Error != nil {
			ca.Error = DNS.Error
			break
		}

		MDNS = syncMdns.New(ca.Host)
		if MDNS.Error != nil {
			ca.Error = MDNS.Error
			break
		}

		ca.Valid = true
	}

	return ca.Error
}

func fillArray(count int, args []string) []string {
	var ret []string
	for range Only.Once {
		if len(args) > count {
			count = len(args)
		}

		ret = make([]string, count)
		for i, e := range args {
			ret[i] = e
		}
	}
	return ret
}
