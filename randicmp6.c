#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <time.h>
#include <pcap.h>
#include "thc-ipv6.h"

int main(int argc, char *argv[]) {
  unsigned char *dst61, *src61;
  unsigned char buf[40];
  int pkt_len = 600;
  char *interface;
  unsigned char *pkt = NULL;
  unsigned char *srcmac, *dstmac;       //can define as null to auto generate
  int type, code, flags = 0;

  if (argc < 2) {
    printf("code by ecore\ncode based on thc-ipv6\n\n");
    printf("Syntax: %s interface destination [source]\n\n", argv[0]);
    printf("Sends all ICMPv6 type and code combinations to destination.\n");
    printf("Set source ipv6 address to spoof.\n");
    exit(0);
  }

  interface = argv[1];
// source and destination ipv6 addresses
  dst61 = thc_resolve6(argv[2]);
  if (argv[3] == NULL && argc > 3)
    src61 = thc_get_own_ipv6(interface, dst61, PREFER_GLOBAL);
  else
    src61 = thc_resolve6(argv[3]);

  memset(buf, 0, sizeof(buf));
  printf("Sending ICMPv6 Packets to %s%%%s\n", argv[2], argv[1]);

  srcmac = thc_get_own_mac(interface);
  dstmac = thc_get_mac(interface, src61, dst61);

  if (srcmac == NULL) {
    fprintf(stderr, "Error: illegal interface: %s\n", interface);
    exit(-1);
  }
  if (dstmac == NULL) {
    fprintf(stderr, "Error: can not resolve target: %s\n", argv[2]);
    exit(-1);
  }

  memset(buf, 0, sizeof(buf));

  for (type = 0; type < 256; type++) {
    printf("Sending ICMPv6 type %d ...\n", type);
    for (code = 0; code < 256; code++) {

//build the packet
      if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, src61, dst61, 0, 0, 0, 0, 0)) == NULL)
        printf("Packet Creation Failed\n");

//add icmp part
      if (thc_add_icmp6(pkt, &pkt_len, type, code, flags, buf, sizeof(buf), 0) < 0)
        return -1;

//generate packet
      if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0) {
        printf("generate failed\n");
        return -1;
      }
// send the packet out
      if (thc_send_pkt(interface, pkt, &pkt_len) < 0)
        printf("packet not sent \n");

      thc_destroy_packet(pkt);  //destroy the packet
      pkt = NULL;
      pkt_len = 0;
      usleep(10000);
    }
  }
  printf("Done!\n");
  return 0;
}
