package syncDns

import (
	"GoSyncDNS/Only"
	"GoSyncDNS/host"
)

func (d *DNS) toHostStruct(ttl string, fqdn string, ip string) *host.Host {
	h := host.New()

	for range Only.Once {
		d.Error = h.SetTtlString(ttl)
		if d.Error != nil {
			break
		}

		d.Error = h.SetHostName(fqdn)
		if d.Error != nil {
			break
		}

		d.Error = h.SetIpAddr(ip)
		if d.Error != nil {
			break
		}
	}

	return h
}
