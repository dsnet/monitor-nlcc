package main

import (
	"bufio"
	"encoding/binary"
	"io"
	"io/fs"
	"log"
	"math/bits"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dsnet/golib/pcap"
	"github.com/dsnet/try"
	influxdb2 "github.com/influxdata/influxdb-client-go/v2"
	"github.com/influxdata/influxdb-client-go/v2/api"
	"golang.org/x/exp/slices"
	"golang.org/x/sync/errgroup"
)

// TODO: Periodically record nslookup results.
// TODO: Periodically ping specific machines.

const (
	ethInterface = "enp1s0"

	pcapInterface = "enp2s0"
	captureSize   = 96

	outputDir  = "/data/pcap"
	rotateSize = 64 << 20
	maxDirSize = 4 << 30
)

type mac [6]byte
type macAddrV4 struct {
	mac  mac
	addr [4]byte
}
type macAddrV6 struct {
	mac  mac
	addr [16]byte
}

var globalStats = struct {
	mu              sync.Mutex
	trafficV4       map[[2]macAddrV4]trafficCounts
	trafficV6       map[[2]macAddrV6]trafficCounts
	unknownEthernet trafficCounts
}{
	trafficV4: make(map[[2]macAddrV4]trafficCounts),
	trafficV6: make(map[[2]macAddrV6]trafficCounts),
}

type trafficCounts struct {
	packets uint64
	bytes   uint64
}

func (c trafficCounts) Add(p pcap.Packet) trafficCounts {
	c.packets++
	c.bytes += uint64(p.OrigLen)
	return c
}

func (c1 trafficCounts) Merge(c2 trafficCounts) trafficCounts {
	return trafficCounts{c1.packets + c2.packets, c1.bytes + c2.bytes}
}

func monitorNetwork(wapi api.WriteAPI, hostMap map[macAddr]string) {
	go pcapUpdateInfluxdb(wapi, hostMap)
	for {
		if err := capturePackets(); err != nil {
			log.Printf("capturePackets: %v", err)
		}
		time.Sleep(5 * time.Second)
	}
}

func capturePackets() (err error) {
	defer try.Handle(&err)

	var group errgroup.Group

	pr, pw := io.Pipe()
	cmd := exec.Command("./tcpdump", "-i", pcapInterface, "-s", strconv.Itoa(captureSize), "-w", "-", "-U")
	cmd.Stdout = pw
	cmd.Stderr = os.Stderr

	var garbageCollecting sync.Mutex
	group.Go(func() error {
		defer pw.Close()
		return cmd.Run()
	})
	group.Go(func() (err error) {
		defer pr.Close()
		defer try.Handle(&err)

		r := try.E1(pcap.NewReader(pr))

		var outputSize int64
		var f *os.File
		defer f.Close()
		var bw bufio.Writer
		var w *pcap.Writer
		for {
			if outputSize > rotateSize || w == nil {
				// Close any previously open output file.
				if w != nil {
					try.E(bw.Flush())
					try.E(f.Close())
				}

				// Open a new output file.
				outName := filepath.Join(outputDir, time.Now().Format("20060102_150405.pcap"))
				f = try.E1(os.OpenFile(outName, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0664))
				bw.Reset(f)

				// Initialize a new packet writer.
				w = try.E1(pcap.NewWriter(&bw, r.Header))
				outputSize = 0

				// Garbage collect old packet captures.
				group.Go(func() (err error) {
					if !garbageCollecting.TryLock() {
						return nil
					}
					defer garbageCollecting.Unlock()

					defer try.Handle(&err)
					ents := try.E1(os.ReadDir(outputDir))
					slices.SortFunc(ents, func(x, y fs.DirEntry) bool {
						return x.Name() < y.Name()
					})
					var totalSize int64
					for _, ent := range ents {
						totalSize += try.E1(ent.Info()).Size()
					}
					for totalSize > maxDirSize && len(ents) > 0 {
						totalSize -= try.E1(ents[0].Info()).Size()
						try.E(os.Remove(filepath.Join(outputDir, ents[0].Name())))
						ents = ents[1:]
					}
					return nil
				})
			}

			p := try.E1(r.ReadNext())
			analyzePacket(p)
			try.E(w.WriteNext(p))
			outputSize += 16 + int64(len(p.Data))
		}
	})

	return group.Wait()
}

func analyzePacket(p pcap.Packet) {
	globalStats.mu.Lock()
	defer globalStats.mu.Unlock()

	if len(p.Data) < 14 {
		globalStats.unknownEthernet.Add(p)
		return // ethernet frame too short
	}
	dstMac := *(*mac)(p.Data[0:6])
	srcMac := *(*mac)(p.Data[6:12])
	etherType := binary.BigEndian.Uint16(p.Data[12:14])
	p.Data = p.Data[14:]
	p.OrigLen -= 14

	switch etherType {
	case 0x0800: // ipV4
		switch {
		case len(p.Data) < 20:
			globalStats.unknownEthernet.Add(p)
			return // ipV4 packet too short
		case p.Data[0]>>4 != 4:
			globalStats.unknownEthernet.Add(p)
			return // non-IPv4 packet
		default:
			src := macAddrV4{srcMac, *(*[4]byte)(p.Data[12:16])}
			dst := macAddrV4{dstMac, *(*[4]byte)(p.Data[16:20])}
			conn := [2]macAddrV4{src, dst}
			globalStats.trafficV4[conn] = globalStats.trafficV4[conn].Add(p)
		}
	case 0x86DD: // ipV6
		switch {
		case len(p.Data) < 40:
			globalStats.unknownEthernet.Add(p)
			return // ipV6 packet too short
		case p.Data[0]>>4 != 6:
			globalStats.unknownEthernet.Add(p)
			return // non-IPv6 packet
		default:
			src := macAddrV6{dstMac, *(*[16]byte)(p.Data[8:24])}
			dst := macAddrV6{srcMac, *(*[16]byte)(p.Data[24:40])}
			conn := [2]macAddrV6{src, dst}
			globalStats.trafficV6[conn] = globalStats.trafficV6[conn].Add(p)
		}
	default:
		globalStats.unknownEthernet.Add(p)
		return // non-IP packet (e.g., ARP, VLAN tag, etc.)
	}
}

func pcapUpdateInfluxdb(wapi api.WriteAPI, hostMap map[macAddr]string) {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	var lastUpdatedPrefixes time.Time
	var localPrefixes []netip.Prefix
	isPrivate := func(a netip.Addr) bool {
		if a.IsMulticast() {
			return false
		}
		if len(localPrefixes) == 0 {
			return a.IsPrivate() || a.IsLinkLocalUnicast()
		}
		for _, prefix := range localPrefixes {
			if prefix.Contains(a) {
				return true
			}
		}
		return false
	}

	// Accumulation of all counts over time.
	var total, wanTotal, lanTotal trafficCounts
	var wanTotalRx, wanTotalTx, lanTotalBx trafficCounts
	var internetUnknown, ethernetUnknown trafficCounts
	lastSeen := make(map[macAddr]time.Time)
	wanRx := make(map[macAddr]trafficCounts)
	wanTx := make(map[macAddr]trafficCounts)
	lanRx := make(map[macAddr]trafficCounts)
	lanTx := make(map[macAddr]trafficCounts)
	lanBx := make(map[macAddr]trafficCounts)

	for now := range ticker.C {
		// Keep a fresh list of local subnets.
		if now.Sub(lastUpdatedPrefixes) > 5*time.Minute {
			b, err := exec.Command("ifconfig", ethInterface).Output()
			var prefixes []netip.Prefix
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				switch {
				case strings.HasPrefix(line, "inet "):
					if fields := strings.Fields(line); len(fields) >= 4 && fields[0] == "inet" && fields[2] == "netmask" {
						ip, err1 := netip.ParseAddr(fields[1])
						nm, err2 := netip.ParseAddr(fields[3])
						if err1 == nil && err2 == nil {
							a := nm.As4()
							pn := 32 - bits.TrailingZeros32(binary.BigEndian.Uint32(a[:]))
							prefixes = append(prefixes, netip.PrefixFrom(ip, pn).Masked())
						}
					} else {
						log.Printf("invalid ifconfig inet line: %v", line)
					}
				case strings.HasPrefix(line, "inet6 "):
					if fields := strings.Fields(line); len(fields) >= 4 && fields[0] == "inet6" && fields[2] == "prefixlen" {
						ip, err1 := netip.ParseAddr(fields[1])
						pn, err2 := strconv.Atoi(fields[3])
						if err1 == nil && err2 == nil {
							prefixes = append(prefixes, netip.PrefixFrom(ip, pn).Masked())
						}
					} else {
						log.Printf("invalid ifconfig inet6 line: %v", line)
					}
				}
			}
			if err != nil {
				log.Printf("ifconfig: %v", err)
			} else if !slices.Equal(localPrefixes, prefixes) {
				log.Printf("local prefixes: %v", prefixes)
				localPrefixes = prefixes
			}
			lastUpdatedPrefixes = now
		}

		// Extract and reset the captured counts.
		globalStats.mu.Lock()
		trafficV4 := globalStats.trafficV4
		trafficV6 := globalStats.trafficV6
		ethernetUnknown = ethernetUnknown.Merge(globalStats.unknownEthernet)
		globalStats.trafficV4 = make(map[[2]macAddrV4]trafficCounts, len(trafficV4))
		globalStats.trafficV6 = make(map[[2]macAddrV6]trafficCounts, len(trafficV6))
		globalStats.unknownEthernet = trafficCounts{}
		globalStats.mu.Unlock()

		// Merge captured counts into accumulative counts.
		updateLastSeen := func(ma macAddr) {
			if _, ok := lastSeen[ma]; !ok {
				log.Printf("caching %v", ma)
			}
			lastSeen[ma] = now
		}
		updateCounters := func(src, dst macAddr, cnts trafficCounts) {
			total = total.Merge(cnts)
			if isPrivate(src.addr) {
				switch {
				case isPrivate(dst.addr): // lan -> lan
					updateLastSeen(dst)
					updateLastSeen(src)
					lanRx[dst] = lanRx[dst].Merge(cnts)
					lanTx[src] = lanTx[src].Merge(cnts)
					lanTotal = lanTotal.Merge(cnts)
				case dst.addr.IsMulticast(): // lan -> any
					updateLastSeen(src)
					lanBx[src] = lanBx[src].Merge(cnts)
					lanTotalBx = lanTotalBx.Merge(cnts)
					lanTotal = lanTotal.Merge(cnts)
				default: // lan -> wan
					updateLastSeen(src)
					wanTx[src] = wanTx[src].Merge(cnts)
					wanTotalTx = wanTotalTx.Merge(cnts)
					wanTotal = wanTotal.Merge(cnts)
				}
			} else {
				switch {
				case isPrivate(dst.addr): // wan -> lan
					updateLastSeen(dst)
					wanRx[dst] = wanRx[dst].Merge(cnts)
					wanTotalRx = wanTotalRx.Merge(cnts)
					wanTotal = wanTotal.Merge(cnts)
				default:
					internetUnknown = internetUnknown.Merge(cnts)
				}
			}
		}
		for conn, cnts := range trafficV4 {
			src := macAddr{conn[0].mac, netip.AddrFrom4(conn[0].addr)}
			dst := macAddr{conn[1].mac, netip.AddrFrom4(conn[1].addr)}
			updateCounters(src, dst, cnts)
		}
		for conn, cnts := range trafficV6 {
			src := macAddr{conn[0].mac, netip.AddrFrom16(conn[0].addr)}
			dst := macAddr{conn[1].mac, netip.AddrFrom16(conn[1].addr)}
			updateCounters(src, dst, cnts)
		}
		total = total.Merge(ethernetUnknown)

		// Stop tracking addresses we have not heard from in a long time.
		for a, seen := range lastSeen {
			if now.Sub(seen) > 5*time.Minute {
				log.Printf("evicting %v", a)
				delete(lastSeen, a)
			}
		}

		ptPackets := influxdb2.NewPointWithMeasurement("network:packets").SetTime(now)
		ptBytes := influxdb2.NewPointWithMeasurement("network:bytes").SetTime(now)
		addFieldPerAddr := func(cntsByAddr map[macAddr]trafficCounts, suffix string) {
			for ma, cnts := range cntsByAddr {
				host, ok := hostMap[ma]
				if !ok {
					host = ma.String()
				}
				label := host + suffix
				if _, ok := lastSeen[ma]; ok {
					ptPackets.AddField(label, cnts.packets)
					ptBytes.AddField(label, cnts.bytes)
				} else {
					ptPackets.AddField(label, uint64(0))
					ptBytes.AddField(label, uint64(0))
					delete(cntsByAddr, ma)
				}
			}
		}
		ptPackets.AddField("total", total.packets)
		ptBytes.AddField("total", total.bytes)
		ptPackets.AddField("total/wan", wanTotal.packets)
		ptBytes.AddField("total/wan", wanTotal.bytes)
		ptPackets.AddField("total/lan", lanTotal.packets)
		ptBytes.AddField("total/lan", lanTotal.bytes)
		ptPackets.AddField("total/lanBx", lanTotalBx.packets)
		ptBytes.AddField("total/lanBx", lanTotalBx.bytes)
		ptPackets.AddField("total/wanRx", wanTotalRx.packets)
		ptBytes.AddField("total/wanRx", wanTotalRx.bytes)
		ptPackets.AddField("total/wanTx", wanTotalTx.packets)
		ptBytes.AddField("total/wanTx", wanTotalTx.bytes)
		ptPackets.AddField("unknown/internet", internetUnknown.packets)
		ptBytes.AddField("unknown/internet", internetUnknown.bytes)
		ptPackets.AddField("unknown/ethernet", ethernetUnknown.packets)
		ptBytes.AddField("unknown/ethernet", ethernetUnknown.bytes)
		addFieldPerAddr(wanRx, "/wanRx")
		addFieldPerAddr(wanTx, "/wanTx")
		addFieldPerAddr(lanRx, "/lanRx")
		addFieldPerAddr(lanTx, "/lanTx")
		addFieldPerAddr(lanBx, "/lanBx")
		wapi.WritePoint(ptPackets)
		wapi.WritePoint(ptBytes)
	}
}
