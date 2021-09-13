package syncDns

import (
	"GoSyncDNS/Only"
	"GoSyncDNS/host"
	"fmt"
	"strings"
	"time"
)

func (d *DNS) toHostStruct(ttl string, fqdn string, ip string) *host.Host {
	h := host.New()

	for range Only.Once {
		d.Error = h.SetTtlString(ttl)
		if d.Error != nil {
			break
		}

		d.Error = h.LastHostname().SetHostName(fqdn)
		if d.Error != nil {
			break
		}

		d.Error = h.LastHostname().SetIpAddr(ip)
		if d.Error != nil {
			break
		}
	}

	return h
}

func (d *DNS) PrintLog(level int, format string, args ...interface{}) error {

	for range Only.Once {
		if format == "" {
			break
		}
		if level > 4 {
			level = 4
		}
		//level += 1

		h := fmt.Sprintf("%s\t- ", time.Now().Format("2006-02-01 15:04:05"))
		h += strings.Repeat("\t", level)

		format = fmt.Sprintf(format, args...)
		//format = strings.ReplaceAll(format, "\n", "\n" + h + "\t")
		fmt.Print(h, format)
	}

	return d.Error
}
