package discover

import (
	"GoSyncDNS/Only"
	"fmt"
	"time"
)

func ScanInterface(ifs string) error {
	var err error

	for range Only.Once {
		var interfaces Interfaces
		interfaces, err = GetInterfaces()
		if err != nil {
			break
		}

		var iface *Interface
		iface, err = interfaces.GetInterface(ifs)
		//iface, err = interfaces.GetFirstInterface()
		if err != nil {
			break
		}

		err = iface.ScanNetwork(time.Second)
		if err != nil {
			break
		}
		iface.ScanClose()

		time.Sleep(time.Second * 5)
		fmt.Printf("END\n")
	}

	return err
}
