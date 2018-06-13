// @Date : 2018-06-13 08:55:37
// @Author : wangwei (winway1988@163.com)
// @Link : https://winway.github.io
// @Version : 0.1
// @Description : 这个家伙很懒，没有留下任何信息
// @History :
// @Other:
//
//      ┏┛ ┻━━━━━┛ ┻┓
//      ┃　　　　　　 ┃
//      ┃　　　━　　　┃
//      ┃　┳┛　  ┗┳　┃
//      ┃　　　　　　 ┃
//      ┃　　　┻　　　┃
//      ┃　　　　　　 ┃
//      ┗━┓　　　┏━━━┛
//        ┃　　　┃   GOD BLESS!
//        ┃　　　┃    NO BUG！
//        ┃　　　┗━━━━━━━━━┓
//        ┃　　　　　　　    ┣┓
//        ┃　　　　         ┏┛
//        ┗━┓ ┓ ┏━━━┳ ┓ ┏━┛
//          ┃ ┫ ┫   ┃ ┫ ┫
//          ┗━┻━┛   ┗━┻━┛

package main

import (
	"flag"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func loadNameServerInfo(fileName string) ([]string, error) {
	content, err := ioutil.ReadFile(fileName)
	if err != nil {
		return []string{}, err
	}

	var nameServers []string
	for _, nameServer := range strings.Split(string(content), "\n") {
		if strings.Contains(nameServer, ":") {
			continue
		} else {
			nameServers = append(nameServers, nameServer)
		}
	}

	log.Printf("Load %d nameserver", len(nameServers))

	return nameServers, nil
}

func dumpIpResult(fileName string, ipMap map[string]struct{}) {
	fd, err := os.Create(fileName)
	if err != nil {
		log.Fatal(err)
	}
	defer fd.Close()

	for ip, _ := range ipMap {
		fd.WriteString(ip + "\n")
	}
}

func sendPacket(device string, nameServers []string, url string) {
	log.Printf("Start sendPacket")

	var (
		snapshotLen int32 = 1024
		promiscuous bool  = false
		err         error
		timeout     time.Duration = 30 * time.Second
		handle      *pcap.Handle
		buffer      gopacket.SerializeBuffer
		options     gopacket.SerializeOptions
	)

	// Open device
	handle, err = pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	for id, nameServer := range nameServers {
		if id%100 == 0 {
			time.Sleep(60 * time.Millisecond)
		}

		ethernetLayer := &layers.Ethernet{
			SrcMAC:       net.HardwareAddr{0x52, 0x54, 0x00, 0x87, 0xcb, 0x73}, // TODO: get dynamically
			DstMAC:       net.HardwareAddr{0xfe, 0xee, 0x0b, 0xca, 0xe5, 0x69}, // TODO: get dynamically
			EthernetType: layers.EthernetTypeIPv4,
		}
		ipLayer := &layers.IPv4{
			Version:  4,
			TTL:      64,
			SrcIP:    net.IP{172, 21, 0, 8}, // TODO: get dynamically
			DstIP:    net.ParseIP(nameServer),
			Protocol: layers.IPProtocolUDP,
		}
		udpLayer := &layers.UDP{
			SrcPort: layers.UDPPort(41435), // TODO: choose dynamically
			DstPort: layers.UDPPort(53),
		}
		udpLayer.SetNetworkLayerForChecksum(ipLayer)
		dnsLayer := &layers.DNS{
			ID:           uint16(id),
			QR:           false,               // DNS request
			OpCode:       layers.DNSOpCode(0), // query
			AA:           false,
			TC:           false,
			RD:           true,
			RA:           false,
			Z:            2,
			ResponseCode: layers.DNSResponseCode(0),
			QDCount:      1,
			ANCount:      0,
			NSCount:      0,
			ARCount:      0,
			Questions:    []layers.DNSQuestion{{Name: []byte(url), Type: layers.DNSType(28), Class: layers.DNSClass(1)}}, // AAAA
		}

		// And create the packet with the layers
		buffer = gopacket.NewSerializeBuffer()
		options = gopacket.SerializeOptions{
			ComputeChecksums: true,
			FixLengths:       true,
		}
		gopacket.SerializeLayers(buffer, options,
			ethernetLayer,
			ipLayer,
			udpLayer,
			dnsLayer,
		)
		outgoingPacket := buffer.Bytes()

		err = handle.WritePacketData(outgoingPacket)
		if err != nil {
			log.Printf("%s", err)
		}
	}

	log.Printf("Complete sendPacket")
}

func capturePacket(device string, url string, ipMap map[string]struct{}) {
	log.Printf("Start capturePacket")

	var (
		snapshotLen int32         = 65535
		promiscuous bool          = true
		timeout     time.Duration = 30 * time.Second
	)

	// Open device
	handle, err := pcap.OpenLive(device, snapshotLen, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Set filter
	var filter string = "udp and src port 53"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Set filter: %s", filter)

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		// Get the DNS layer from this packet
		if dnsLayer := packet.Layer(layers.LayerTypeDNS); dnsLayer != nil {
			dns, _ := dnsLayer.(*layers.DNS)

			for _, qus := range dns.Questions {
				if string(qus.Name) == url && qus.Type == 28 {
					for _, ans := range dns.Answers {
						if ans.Type == 28 {
							ipMap[ans.IP.String()] = struct{}{}
						}
					}
					break
				}
			}
		}
	}
}

func main() {
	var url string
	flag.StringVar(&url, "url", "", "Url to dig")
	flag.Parse()
	if url == "" {
		log.Fatal("Url is null")
	}
	log.Printf("Start to dig url: %s", url)

	ipMap := make(map[string]struct{})   // 存储IP结果集
	go capturePacket("eth0", url, ipMap) // 开启捕包

	// 加载DNS服务器列表
	nameServers, err := loadNameServerInfo("./conf/nameservers.txt")
	if err != nil {
		log.Fatal(err)
	}
	sendPacket("eth0", nameServers, url) // 发送DNS查询请求

	ipNum := len(ipMap)
	sameCounter := 0
	for {
		time.Sleep(1 * time.Second)
		if ipNum == len(ipMap) {
			sameCounter += 1
		} else {
			sameCounter = 0
			log.Printf("Waiting ...")
		}
		ipNum = len(ipMap)

		if sameCounter >= 3 {
			log.Printf("Get %d ip for %s", ipNum, url)
			break
		}
	}

	dumpIpResult("./result/"+url+".ip.txt", ipMap)
}
