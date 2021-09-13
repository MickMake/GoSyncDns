package syncMdns

import (
	"GoSyncDNS/Only"
	"context"
	"errors"
	"fmt"
	"github.com/davecgh/go-spew/spew"
	"github.com/grandcat/zeroconf"
	"regexp"
	"strings"
	"time"
)

type MDNS struct {
	Domain string
	Error  error
	Debug  bool

	OutputType
	SheetId string
}

const (
	TypeJson   = iota
	TypeHuman  = iota
	TypeGoogle = iota
)

type OutputType int

func New(url string) *MDNS {
	var p MDNS

	p.OutputType = TypeHuman

	return &p
}

type ActionFunc func(*MDNS, *zeroconf.ServiceEntry) error

const DefaultWait = time.Second * 120

func (m *MDNS) Scan(wait string, service string, fn ActionFunc) error {

	for range Only.Once {
		delay := DefaultWait
		if wait != "" {
			delay, m.Error = time.ParseDuration(wait)
			if m.Error != nil {
				delay = DefaultWait
			}
		}

		if m.Domain == "" {
			m.Domain = "local."
		}

		if fn == nil {
			fn = PrintEntry
		}

		// Discover all services on the network (e.g. _workstation._tcp)
		var resolver *zeroconf.Resolver
		resolver, m.Error = zeroconf.NewResolver(nil)
		if m.Error != nil {
			m.Error = errors.New("Failed to initialize resolver: " + m.Error.Error())
			break
		}

		entries := make(chan *zeroconf.ServiceEntry)
		go func(results <-chan *zeroconf.ServiceEntry) {
			for entry := range results {
				m.Error = fn(m, entry)
				if m.Error != nil {
					continue
				}
			}
		}(entries)

		var ctx context.Context
		var cancel context.CancelFunc
		if delay == 0 {
			ctx, cancel = context.WithCancel(context.Background())
		} else {
			ctx, cancel = context.WithTimeout(context.Background(), delay)
		}
		defer cancel()

		service = "_services._dns-sd._udp"
		service = "_workstation._tcp"
		service = "_ssh._tcp"
		service = "_tcp"
		service = ""

		m.Error = resolver.Browse(ctx, service, m.Domain, entries)
		if m.Error != nil {
			m.Error = errors.New("Failed to browse: " + m.Error.Error())
			break
		}

		<-ctx.Done()

		if m.Debug {
			fmt.Println("Services found:")
			spew.Dump(entries)
		}
	}

	return m.Error
}

func PrintEntry(m *MDNS, entry *zeroconf.ServiceEntry) error {
	for range Only.Once {
		reg := regexp.MustCompile(`^(\w+:\w+:\w+:\w+:\w+:\w+).*`)
		// instance:b0:8c:75:25:20:f7\@fe80::b28c:75ff:fe25:20f7._apple-mobdev2._tcp..local.
		//log.Println(entry)
		//fmt.Printf("%s\t%s\t# Port:%d Text:%s TTL:%d\tS:%s I:%s D:%s s:%s i:%s d:%s\n",
		//	entry.AddrIPv4,
		//	entry.HostNames,
		//	entry.Port,
		//	strings.Join(entry.Text, " "),
		//	entry.TTL,
		//	entry.ServiceRecord.Service,
		//	entry.ServiceRecord.Instance,
		//	entry.ServiceRecord.Domain,
		//	entry.ServiceName(),
		//	entry.ServiceInstanceName(),
		//	entry.ServiceTypeName(),
		//)

		mac := entry.ServiceInstanceName()
		mac = reg.ReplaceAllString(mac, "$1")
		fmt.Printf("\n%s\t%s\n\t# mac:%s\n\t# Port:%d\n\t# TTL:%d\n\t# type:%s\n\t# Text:%s\n",
			entry.AddrIPv4,
			entry.HostName,
			mac,
			entry.Port,
			entry.TTL,
			entry.ServiceTypeName(),
			strings.Join(entry.Text, " "),
		)
	}

	return m.Error
}

func AddToDNS(m *MDNS, entry *zeroconf.ServiceEntry) error {
	for range Only.Once {
		reg := regexp.MustCompile(`^(\w+:\w+:\w+:\w+:\w+:\w+).*`)
		// instance:b0:8c:75:25:20:f7\@fe80::b28c:75ff:fe25:20f7._apple-mobdev2._tcp..local.
		//log.Println(entry)
		//fmt.Printf("%s\t%s\t# Port:%d Text:%s TTL:%d\tS:%s I:%s D:%s s:%s i:%s d:%s\n",
		//	entry.AddrIPv4,
		//	entry.HostNames,
		//	entry.Port,
		//	strings.Join(entry.Text, " "),
		//	entry.TTL,
		//	entry.ServiceRecord.Service,
		//	entry.ServiceRecord.Instance,
		//	entry.ServiceRecord.Domain,
		//	entry.ServiceName(),
		//	entry.ServiceInstanceName(),
		//	entry.ServiceTypeName(),
		//)

		mac := entry.ServiceInstanceName()
		mac = reg.ReplaceAllString(mac, "$1")
		fmt.Printf("%s\t%s\t# Port:%d Text:%s TTL:%d mac:%s type:%s\n",
			entry.AddrIPv4,
			entry.HostName,
			entry.Port,
			strings.Join(entry.Text, " "),
			entry.TTL,
			mac,
			entry.ServiceTypeName(),
		)
	}

	return m.Error
}
