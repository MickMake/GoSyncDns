package discover

import (
	"GoSyncDNS/Only"
	"encoding/json"
	"fmt"
	"net"
)

type Mac struct {
	Address net.HardwareAddr
}

func (ma *Mac) IsValid() bool {
	var ok bool

	for range Only.Once {
		if ma.Address != nil {
			ok = true
			break
		}
	}

	return ok
}
func (ma *Mac) IsNotValid() bool {
	return !ma.IsValid()
}

func (ma *Mac) Set(mac net.HardwareAddr) error {
	var err error

	for range Only.Once {
		//if mac.String() == BroadcastMAC.String() {
		//	fmt.Printf("BROADCAST '%v' -> '%v'\n", mac, *ma)
		//	break
		//}

		if mac.String() == "" {
			fmt.Printf("EMPTY '%v' -> '%s'\n", mac, ma.String())
			break
		}

		if ma.String() != "" {
			fmt.Printf("ALREADY SET %v -> %s\n", mac, ma.String())
		} else {
			//fmt.Printf("SET %v\n", mac)
		}

		ma.Address = mac
	}

	return err
}

func (ma *Mac) SetString(mac string) error {
	var err error

	for range Only.Once {
		var m net.HardwareAddr
		m, err = net.ParseMAC(mac)
		if err != nil {
			break
		}

		err = ma.Set(m)
	}

	return err
}

func (ma *Mac) Equals(mac net.HardwareAddr) bool {
	var ok bool
	if ma.String() == mac.String() {
		ok = true
	}
	return ok
}

func (ma *Mac) NotEquals(mac net.HardwareAddr) bool {
	return !ma.Equals(mac)
}

func (ma *Mac) String() string {
	//ret := fmt.Sprintf("%s", getString(ma.HardwareAddr))
	return ma.Address.String()
}

func (ma *Mac) Get() net.HardwareAddr {
	//m, _ := net.ParseMAC(getString(ma.HardwareAddr))
	return ma.Address
}

func (ma *Mac) GetMac() MacAddress {
	return MacAddress(ma.Address.String())
}

//type Marshaler interface {
//	MarshalJSON() ([]byte, error)
//}
//
//type Unmarshaler interface {
//	UnmarshalJSON([]byte) error
//}

func (ma *Mac) MarshalJSON() ([]byte, error) {
	type Alias Mac
	m := &struct {
		MacAddress `json:"address"`
		//net.HardwareAddr
		//*Alias
	}{
		MacAddress: ma.GetMac(),
		//HardwareAddr: ma.Get(),
		//Alias: (*Alias)(ma),
	}
	return json.Marshal(&m)
}

func (ma *Mac) UnmarshalJSON(data []byte) error {
	type Alias Mac
	m := &struct {
		MacAddress `json:"address"`
		//*Alias
	}{
		MacAddress: ma.GetMac(),
		//Alias: (*Alias)(ma),
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	return nil
}
