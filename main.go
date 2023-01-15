package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"

	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"tailscale.com/util/must"
)

const (
	influxURL   = "http://localhost:8086"
	influxToken = "II7X6DOdHGYMsDLxkqucj9F4bUxdYWOX16jI2cKmXc6INi8DiWhd_ko10Hsyr2zCuZTRLi14OJiizH4ae2609w=="

	influxOrganization = "nlcc"
	influxBucket       = "nlcc"

	hostmapJSON = "hostmap.json"
)

func main() {
	log.SetFlags(log.Lshortfile) // journalctl records the date for us

	client := influxdb2.NewClient(influxURL, influxToken)
	defer client.Close()
	wapi := client.WriteAPI(influxOrganization, influxBucket)
	go func() {
		for range wapi.Errors() {
		}
	}()

	var rawHostMap map[string]string
	must.Do(json.Unmarshal(must.Get(os.ReadFile(hostmapJSON)), &rawHostMap))
	hostMap := map[macAddr]string{}
	for ma, host := range rawHostMap {
		fs := strings.Fields(ma)
		mac := *(*[6]byte)(must.Get(hex.DecodeString(strings.ReplaceAll(fs[0], "-", ""))))
		addr := must.Get(netip.ParseAddr(fs[1]))
		hostMap[macAddr{mac, addr}] = host
	}

	go monitorNetwork(wapi, hostMap)

	select {}
}

type macAddr struct {
	mac  [6]byte
	addr netip.Addr
}

func (ma macAddr) String() string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x/%s", ma.mac[0], ma.mac[1], ma.mac[2], ma.mac[3], ma.mac[4], ma.mac[5], ma.addr)
}
