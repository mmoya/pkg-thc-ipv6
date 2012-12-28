#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <netdb.h>
#include <pcap.h>
#include "thc-ipv6.h"

#define MAX_ALIVE   65536
#define MAX_NETS    256
#define MAX_VENDID  64
#define MAX_PORTS   16
#define RESP_PONG   "ICMP echo-reply"
#define RESP_UNREACH_PORT    "ICMP port unreachable"
#define RESP_UNREACH_ROUTE   "ICMP network unreachable"
#define RESP_UNREACH_FW      "ICMP firewalled unreachable"
#define RESP_UNREACH_OOSCOPE "ICMP out of scope unreachable"
#define RESP_UNREACH_ADDR    "ICMP host unreachable"
#define RESP_UNREACH_GRESS   "ICMP ingress/egress filter unreachable"
#define RESP_UNREACH_REJECT  "ICMP route reject unreachable"
#define RESP_TOOBIG    "ICMP packet too big"
#define RESP_TTLEXCEED "ICMP TTL exceeded"
#define RESP_REDIR     "ICMP local router traffic redirect"
#define RESP_PARAMPROB "ICMP parameter problem"
#define RESP_ERROR     "ICMP error"
#define RESP_UDP    "UDP"
#define RESP_SYNACK "TCP SYN-ACK"
#define RESP_RST    "TCP RST"
#define RESP_ACK    "TCP ACK"
#define RESP_OTHER  "TCP misc-options"
#define RESP_UNKNOWN "unknown"

unsigned char buf[8], *alive[MAX_ALIVE];
int alive_no = 0, resolve = 0, waittime = 1, rawmode = 0;
int synports[MAX_PORTS], ackports[MAX_PORTS], udpports[MAX_PORTS];
int do_ping = 1, do_dst = 1, do_hop = 0, verbose = 0;
unsigned long int tcount = 0;
FILE *out = NULL;
struct hostent *he = NULL;
short int si, sp, sp2;

// all dict entries must start with a single from/to 0,0,0,0
// and end with a single from/to ffff,ffff,ffff,ffff
unsigned short int dict[] = { 0, 0, 0, 0, /*to */ 0, 0, 0, 0,
  0, 0, 0, 1, /*to */ 0, 0, 0, 0x2ff,   // 1975 tests
  0, 0, 0, 0x300, /*to */ 0, 0, 0, 0x305,
  0, 0, 0, 0x400, /*to */ 0, 0, 0, 0x405,
  0, 0, 0, 0x500, /*to */ 0, 0, 0, 0x505,
  0, 0, 0, 0x530, /*to */ 0, 0, 0, 0x53f,
  0, 0, 0, 0x555, /*to */ 0, 0, 0, 0x555,
  0, 0, 0, 0x600, /*to */ 0, 0, 0, 0x605,
  0, 0, 0, 0x666, /*to */ 0, 0, 0, 0x667,
  0, 0, 0, 0x700, /*to */ 0, 0, 0, 0x703,
  0, 0, 0, 0x800, /*to */ 0, 0, 0, 0x803,
  0, 0, 0, 0x900, /*to */ 0, 0, 0, 0x903,
  0, 0, 0, 0xaaa, /*to */ 0, 0, 0, 0xaaa,
  0, 0, 0, 0xff0, /*to */ 0, 0, 0, 0xfff,
  0, 0, 0, 0x1000, /*to */ 0, 0, 0, 0x1111,
  0, 0, 0, 0x2000, /*to */ 0, 0, 0, 0x2111,
  0, 0, 0, 0x3000, /*to */ 0, 0, 0, 0x3011,
  0, 0, 0, 0x1337, /*to */ 0, 0, 0, 0x1337,
  0, 0, 0, 0x3128, /*to */ 0, 0, 0, 0x3128,
  0, 0, 0, 0x2525, /*to */ 0, 0, 0, 0x2525,
  0, 0, 0, 0x5353, /*to */ 0, 0, 0, 0x5353,
  0, 0, 0, 0x6666, /*to */ 0, 0, 0, 0x6667,
  0, 0, 0, 0x8000, /*to */ 0, 0, 0, 0x8000,
  0, 0, 0, 0x8080, /*to */ 0, 0, 0, 0x8080,
  0, 0, 0, 0xaaaa, /*to */ 0, 0, 0, 0xaaaa,
  0, 0, 0, 0xabcd, /*to */ 0, 0, 0, 0xabcd,
  0, 0, 0, 0xbabe, /*to */ 0, 0, 0, 0xbabe,
  0, 0, 0, 0xbeef, /*to */ 0, 0, 0, 0xbeef,
  0, 0, 0, 0xcafe, /*to */ 0, 0, 0, 0xcafe,
  0, 0, 0, 0xc0de, /*to */ 0, 0, 0, 0xc0de,
  0, 0, 0, 0xdead, /*to */ 0, 0, 0, 0xdead,
  0, 0, 0, 0xf500, /*to */ 0, 0, 0, 0xf500,
  0, 0, 0, 0xfeed, /*to */ 0, 0, 0, 0xfeed,
  0, 0, 0, 0xfff0, /*to */ 0, 0, 0, 0xffff,
  0, 0, 1, 0, /*to */ 0, 0, 1, 0x1ff,
  0, 0, 2, 0, /*to */ 0, 0, 0x119, 5,
  0, 0, 2, 0xa, /*to */ 0, 0, 2, 0x20,
  0, 0, 2, 0x21, /*to */ 0, 0, 3, 0x21,
  0, 0, 2, 0x22, /*to */ 0, 0, 3, 0x22,
  0, 0, 2, 0x25, /*to */ 0, 0, 9, 0x25,
  0, 0, 2, 0x53, /*to */ 0, 0, 9, 0x53,
  0, 0, 2, 0x80, /*to */ 0, 0, 9, 0x80,
  0, 0, 2, 0x500, /*to */ 0, 0, 9, 0x500,
  0, 0, 2, 6, /*to */ 0, 0, 9, 9,
  0, 0, 0xa, 0, /*to */ 0, 0, 0xf, 2,
  0, 0, 0x80, 6, /*to */ 0, 0, 0x80, 0x1f,
  0, 0, 0x200, 0, /*to */ 0, 0, 0x200, 3,
  0, 0, 0x389, 0, /*to */ 0, 0, 0x389, 3,
  0, 0, 0x443, 0, /*to */ 0, 0, 0x443, 3,
  0, 0, 0x500, 0, /*to */ 0, 0, 0x500, 2,
  0, 0, 0x666, 0, /*to */ 0, 0, 0x669, 2,
  0, 0, 0x3128, 0, /*to */ 0, 0, 0x3128, 3,
  0, 0, 0x6666, 0, /*to */ 0, 0, 0x6669, 2,
  0, 0, 0x8080, 0, /*to */ 0, 0, 0x8080, 3,
  0, 0, 0xdead, 0xbeef, /*to */ 0, 0, 0xdead, 0xbeef,
//  0, 1, 0, 0, /*to */ 0, 3, 3, 3,
  0, 0, 0, 0, /*to */ 4, 4, 4, 4,  // some doubles here
  1, 0, 0, 5, /*to */ 1, 0, 0, 0xf,
//  2, 0, 1, 0, /*to */ 2, 0, 1, 3,
  2, 0, 0, 5, /*to */ 2, 0, 0, 0xd,
//  1, 2, 3, 4, /*to */ 1, 2, 3, 4,
  5, 0, 0, 1, /*to */ 0xff, 0, 0, 2,
  0xffff, 0x00ff, 0xfe00, 0xfffe, /*to */ 0xffff, 0x00ff, 0xfe00, 0xffff,
  0xffff, 0xffff, 0xffff, 0xfffe, /*to */ 0xffff, 0xffff, 0xffff, 0xfffe,
  0xffff, 0xffff, 0xffff, 0xffff, /*to */ 0xffff, 0xffff, 0xffff, 0xffff
};

// more keywords:
// cafe, dead, beef, affe, b00b, babe, f00, fefe, ffff, 1337, 666, 0, 1

/* unsigned short int dict_small[] = { 0, 0, 0, 0,    0, 0, 0, 0, // required
                          // more to come here
                        0xffff, 0xffff, 0xffff, 0xffff,    0xffff, 0xffff, 0xffff, 0xffff // required
                      };*/

void help(char *prg) {
  printf("%s %s (c) 2012 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf ("Syntax: %s [-I srcip6] [-i file] [-o file] [-DM] [-p] [-F] [-e opt] [-s port,..] [-a port,..] [-u port,..] [-W TIME] [-dlrvS] interface [unicast-or-multicast-address [remote-router]]\n\n", prg);
  printf("Shows alive addresses in the segment. If you specify a remote router, the\n");
  printf("packets are sent with a routing header prefixed by fragmentation\n");
  printf("Options:\n");
  printf("  -i file    check systems from input file\n");
  printf("  -o file    write results to output file\n");
  printf("  -M         enumerate hardware addresses (MAC) from input addresses (slow!)\n");
  printf("  -D         enumerate DHCP address space from input addresses\n");
  printf("  -p         send a ping packet for alive check (default)\n");
  printf("  -e dst,hop send an errornous packets: destination (default), hop-by-hop\n");
  printf("  -s port,port,..  TCP-SYN packet to ports for alive check\n");
  printf("  -a port,port,..  TCP-ACK packet to ports for alive check\n");
  printf("  -u port,port,..  UDP packet to ports for alive check\n");
//  printf("  -F         firewall mode: -p -e dst,hop -u 53 -s 22,25,80,443,9511 -a 9511\n");
  printf("  -d         DNS resolve alive ipv6 addresses\n");
  printf("  -n number  how often to send each packet (default: local 1, remote 2)\n");
  printf("  -W time    time in ms to wait after sending a packet (default: %d)\n", waittime);
  printf("  -S         slow mode, get best router for each remote target or when proxy-NA\n");
  printf("  -I srcip6  use the specified IPv6 address as source\n");
  printf("  -l         use link-local address instead of global address\n");
//  printf("  -r         use raw mode (for tunnels)\n");
  printf("  -v         verbose (twice: detailed information, thrice: dumping all packets)\n");
  printf("Target address on command line or in input file can include ranges in the form\n");
  printf("of 2001:db8::1-fff or 2001:db8::1-2:0-ffff:0:0-ffff, etc.\n");
  printf("Returns -1 on errors, 0 if a system was found alive or 1 if nothing was found.\n");
  exit(-1);
}

void check_packets(u_char *foo, const struct pcap_pkthdr *header, const unsigned char *data) {
  int i, ok = 0, len = header->caplen, offset = 0, nxt;
  unsigned char *ptr = (unsigned char *) data, *p1, *p2, *p3, sport[16] = "", *orig_dst = NULL;
  char *type = RESP_UNKNOWN;

  if (!rawmode) {
    ptr += 14;
    len -= 14;
  }
  if (do_hdr_size) {
    ptr += (do_hdr_size - 14);
    len -= (do_hdr_size - 14);
    if ((ptr[0] & 240) != 0x60)
      return;
  }

  if (debug)
    thc_dump_data(ptr, len, "Received Packet");

  if (len < 48 + sizeof(buf))
    return;

  nxt = ptr[6];

  // if the destination system sends source routed packets back, unlikely though
//  if (ptr[6] == NXT_ROUTE) 
//    if ((offset = (ptr[41] + 1) * 8) + 48 + sizeof(buf) > len)
//      return;

  if (ptr[6 + offset] == NXT_FRAG) {
    nxt = ptr[40 + offset]; 
    offset += 8;
  }

  if (nxt == NXT_ICMP6 && (do_ping || do_dst || do_hop || udpports[0] != -1)) {
    if (ptr[40 + offset] == ICMP6_PINGREPLY && (do_ping || do_dst || do_hop)) {
      if (memcmp(ptr + 50 + offset, (char *) &si, 2) == 0) {
        ok = 1;
        type = RESP_PONG;
      }
    } else                      // if not a ping reply, its an error packet and the size is larger
    if (len < 96 + sizeof(buf))
      return;
    if (ptr[40 + offset] == ICMP6_PARAMPROB && (do_dst || do_hop))
      if (memcmp(ptr + len - 4, (char *) &si, 2) == 0) {
        ok = 1;
        type = RESP_PARAMPROB;
      }
    if (ptr[40 + offset] == ICMP6_UNREACH && ptr[41 + offset] == 4 && udpports[0] != -1)
      if (memcmp(ptr + 88 + offset, (char *) &sp2, 2) == 0) {
        ok = 1;
        type = RESP_UNREACH_PORT;
        i = (ptr[90 + offset] << 8) + ptr[91 + offset];
        snprintf(sport, sizeof(sport), "%d/", i);
      }
  }

  if (nxt == NXT_UDP && udpports[0] != -1)
    if (memcmp(ptr + 42 + offset, (char *) &sp2, 2) == 0) {
      ok = 1;
      type = RESP_UDP;
    }

  if (nxt == NXT_TCP && (synports[0] != -1 || ackports[0] != -1))
    if (memcmp(ptr + 42 + offset, (char *) &sp2, 2) == 0) {
      ok = 1;
      i = ptr[41 + offset] + (ptr[40 + offset] << 8);
      snprintf(sport, sizeof(sport), "%d/", i);
      switch (ptr[53 + offset]) {
      case (TCP_SYN + TCP_ACK):
        type = RESP_SYNACK;
        break;
      case TCP_ACK:
        type = RESP_ACK;
        break;
      case TCP_RST:            /* fall through */
      case (TCP_RST + TCP_ACK):
        type = RESP_RST;
        break;
      default:
        type = RESP_OTHER;
      }
    }

  if (ok == 0 && nxt == NXT_ICMP6) {
    ok = 1;
    switch (ptr[40 + offset]) {
    case 1:
      switch (ptr[41 + offset]) {
      case 0:
        type = RESP_UNREACH_ROUTE;
        break;
      case 1:
        type = RESP_UNREACH_FW;
        break;
      case 2:
        type = RESP_UNREACH_OOSCOPE;
        break;
      case 3:
        type = RESP_UNREACH_ADDR;
        break;
      case 4:
        type = RESP_UNREACH_PORT;
        break;
      case 5:
        type = RESP_UNREACH_GRESS;
        break;
      case 6:
        type = RESP_UNREACH_REJECT;
        break;
      default:
        ok = 0;
      }
      break;
    case 2:
      type = RESP_TOOBIG;
      break;
    case 3:
      type = RESP_TTLEXCEED;
      break;
    case 4:
      type = RESP_PARAMPROB;
      break;
    case 137:
      type = RESP_REDIR;
      break;
    default:
      ok = 0;
    }
    if (ok == 0) {
      type = RESP_ERROR;
      snprintf(sport, sizeof(sport), "%d:%d/", ptr[40], ptr[41]);
      ok = 1;
    } else
      orig_dst = thc_ipv62notation(ptr + 72 + offset);
  }

  i = 0;
  if (verbose < 2)
    while (ok && i < alive_no) {
      if (memcmp(alive[i], ptr + 8 + offset, 16) == 0)
        ok = 0;
      i++;
    }

  if (ok) {
    if (resolve)
      he = gethostbyaddr(ptr + 8, 16, AF_INET6);
    p2 = thc_ipv62notation(ptr + 8);
    printf("Alive: %s%s%s%s [%s%s%s%s]\n", p2, resolve ? " (" : "", resolve
           && he != NULL ? he->h_name : "", resolve ? ")" : "", sport, type, orig_dst != NULL ? " for " : "", orig_dst != NULL ? (char *) orig_dst : "");
    if (out != NULL)
      fprintf(out, "%s%s%s%s\n", p2, resolve ? " (" : "", (resolve && he != NULL) ? he->h_name : "", resolve ? ")" : "");
    free(p2);
    if (orig_dst != NULL)
      free(orig_dst);
    if (alive_no < MAX_ALIVE && (alive[alive_no] = malloc(16)) != NULL) {
      memcpy(alive[alive_no], ptr + 8, 16);
      alive_no++;
      if (alive_no == MAX_ALIVE)
        fprintf(stderr, "Warning: more than %d alive systems detected, disabling double results check!\n", MAX_ALIVE);
    }
  } else if (verbose && len >= 96 + sizeof(buf) && nxt == NXT_ICMP6 && ptr[41 + offset] != 4 && ptr[40 + offset] < 4 && ptr[40 + offset] > 0
             && ptr[40 + 8 + offset + 6] == NXT_ICMP6) {
    if (memcmp(ptr + len - 4, (char *) &si, 2) == 0) {
      if (resolve)
        he = gethostbyaddr(ptr + 8, 16, AF_INET6);
      p2 = thc_ipv62notation(ptr + 8);
      p3 = thc_ipv62notation(ptr + 24 + 40 + 8 + offset);
      switch (ptr[40 + offset]) {
      case 1:
        p1 = "unreachable";
        break;
      case 2:
        p1 = "toobig";
        break;
      case 3:
        p1 = "time-to-live-exceeded";
        break;
      }
      printf("Warning: %s%s%s%s sent an ICMP %s for %s\n", p2, resolve ? " (" : "", resolve && he != NULL ? he->h_name : "", resolve ? ")" : "", p1, p3);
      free(p2);
      free(p3);
    }
  }
}

void get_ports_from_cmdline(int ports[], char *list, char param) {
  int p, c = 0;
  char mylist[strlen(list + 1)], *ptr, *ptr2;

  if (strtok(list, "0123456789,") != NULL) {
    fprintf(stderr, "Error: ports must be defined by numbers and seperated by a comma, e.g. \"-%c 22,53,80\"\n", param);
    exit(-1);
  }
  strcpy(mylist, list);
  ptr = mylist;
  do {
    if (c == MAX_PORTS) {
      fprintf(stderr, "Error: a maximum number of %d ports can be specified\n", MAX_PORTS);
      exit(-1);
    }
    if ((ptr2 = index(ptr, ',')) != NULL)
      *ptr2++ = 0;
    p = atoi(ptr);
    if (p < 0 || p > 65535) {   // allow port zero
      fprintf(stderr, "Error: ports must be between 0 and 65535: %s\n", ptr);
      exit(-1);
    }
    ports[c] = p % 65536;
    c++;
    ptr = ptr2;
  } while (ptr2 != NULL);
}

int main(int argc, char *argv[]) {
  unsigned char string[64]; // = "ip6 and dst ";
  unsigned char *pkt = NULL, *router6 = NULL, *cur_dst, *p2, *p3, *smac, buf2[6];
  unsigned char *multicast6 = NULL, *src6 = NULL, *mac = NULL, *rmac = NULL, *routers[2];
  int pkt_len = 0, prefer = PREFER_GLOBAL, fromto = 0, dictptr = 0, offset = 14;
  int enumerate_mac = 0, enumerate_dhcp = 0, i, j, k, list = 0, curr = 0, cur_enum = 0;
  int slow = 0, no_vendid = 0, no_nets = 0, local = -1, no_send = 1, no_send_local = 1, no_send_remote = 2, nos = 0;
  char *interface = NULL, *input = NULL, *output = NULL, line[128], line2[128], *ptr, *ptr2, *ptr3, do_router = 0, ok;
  unsigned char bh, bm, bl, restart, use_dmac = 0, dump_all = 0;
  unsigned short int ip1, ip2, ip3, ip4, cip1, cip2, cip3, cip4, cip5, cip6, cip7, cip8;
  unsigned short int fip1, fip2, fip3, fip4, fip5, fip6, fip7, fip8, tip1, tip2, tip3, tip4, tip5, tip6, tip7, tip8;
  unsigned char vendid[MAX_VENDID][11], nets[MAX_NETS][8], orig_dst[16], dmac[27] = { 0, 0, 0, 0, 0, 0, 0 };
//  unsigned char dns4buf[] = { 0xde, 0xad, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
//                    0x00, 0x00, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
//                    0x68, 0x6f, 0x73, 0x74, 0x00, 0x00, 0x01, 0x00, 0x01 };
  unsigned char dns6buf[] = { 0xba, 0xbe, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x6c,
    0x68, 0x6f, 0x73, 0x74, 0x00, 0x00, 0x1c, 0x00, 0x01
  };
  thc_ipv6_hdr *hdr;
  time_t passed;
  pcap_t *p;
  FILE *in = NULL;
  time_t timeval;

  for (i = 0; i < MAX_PORTS; i++)
    udpports[i] = ackports[i] = synports[i] = -1;

  if (argc < 2 || strncmp(argv[1], "-h", 2) == 0)
    help(argv[0]);

  j = 0;
  while ((i = getopt(argc, argv, "W:SFdrlMDn:i:o:pvs:a:u:e:VZ:I:X")) >= 0) {
    switch (i) {
    case 'Z':
      use_dmac = 1;
      sscanf(optarg, "%x:%x:%x:%x:%x:%x", (unsigned int *) &dmac[0], (unsigned int *) &dmac[1], (unsigned int *) &dmac[2], (unsigned int *) &dmac[3], (unsigned int *) &dmac[4],
             (unsigned int *) &dmac[5]);
      break;
    case 'W':
      waittime = atoi(optarg);
      break;
    case 'S':
      slow = 1;
      break;
    case 'V':
      debug = 1;
      break;
    case 'F':
      do_ping = 1;
      do_dst = 1;
      do_hop = 1;
      udpports[0] = 53;
      ackports[0] = 9511;
      synports[0] = 22;
      synports[1] = 25;
      synports[2] = 80;
      synports[3] = 443;
      synports[4] = 9511;
      break;
    case 'd':
      resolve = 1;
      break;
    case 'r':
      thc_ipv6_rawmode(1);
      rawmode = 1;
      break;
    case 'l':
      prefer = PREFER_LINK;
      break;
    case 'M':
      enumerate_mac = 1;
      break;
    case 'D':
      enumerate_dhcp = 1;
      break;
    case 'n':
      no_send_local = no_send_remote = atoi(optarg);
      break;
    case 'I':
      if ((src6 = thc_resolve6(optarg)) == NULL) {
        fprintf(stderr, "Error: unable to resolve IPv6 source address %s\n", optarg);
        exit(-1);
      }
      break;
    case 'i':
      input = optarg;
      list++;
      curr = 1;
      break;
    case 'o':
      output = optarg;
      break;
    case 'p':
      do_ping = 1;
      j = (j | 1);
      break;
    case 'v':
      verbose++;
      break;
    case 's':
      j = (j | 8);
      get_ports_from_cmdline(synports, optarg, 's');
      break;
    case 'a':
      j = (j | 8);
      get_ports_from_cmdline(ackports, optarg, 'a');
      break;
    case 'u':
      j = (j | 8);
      get_ports_from_cmdline(udpports, optarg, 'u');
      break;
    case 'e':
      if (index(optarg, ',') != 0) {
        do_dst = 1;
        do_hop = 1;
        j = (j | 6);
      } else {
        if (strncasecmp(optarg, "dst", 3) == 0 || strncasecmp(optarg, "dest", 4) == 0) {
          do_dst = 1;
          j = (j | 4);
        }
        if (strncasecmp(optarg, "hop", 3) == 0) {
          do_hop = 1;
          j = (j | 2);
        }
        if (do_hop + do_dst == 0) {
          fprintf(stderr, "Error: unknown options to error packet option: %s\n", optarg);
          exit(-1);
        }
      }
      break;
    case 'X':
      dump_all = 1;
      break;
    default:
      fprintf(stderr, "Error: unknown option -%c\n", i);
      exit(-1);
    }
  }

  if (j) {                      // reset defaults if an alive check type was chosen
    if ((j & 1) == 0)
      do_ping = 0;
    if ((j & 2) == 0)
      do_hop = 0;
    if ((j & 4) == 0)
      do_dst = 0;
  }

  if (verbose > 1)
    fprintf(stderr, "Warning: -vv disables duplicate checks, every packet will be logged.\n");

  if (no_send < 1 || no_send > 10) {
    fprintf(stderr, "Error: -n option may only be set between 1 and 10\n");
    exit(-1);
  }
  if (waittime < 0) {
    fprintf(stderr, "Error: -W wait time is not a positive value\n");
    exit(-1);
  }
  
  if (do_hdr_size)
    offset = do_hdr_size;

  interface = argv[optind];
  if (argv[optind + 1] != NULL && argc >= optind + 2) {
    ptr = argv[optind + 1];
    curr = 0;
  } else
    ptr = "ff02::1";
  if (ptr != NULL) { // && (index(ptr, ':') == NULL || index(ptr, '-') == NULL)) {
    if (verbose > 1)
      printf("Resolving %s ...\n", ptr);
    multicast6 = thc_resolve6(ptr);     // if it cant resolve - no problem
  }
  if (interface == NULL) {
    fprintf(stderr, "Error: no interface defined!\n");
    exit(-1);
  }
  if (multicast6 != NULL && multicast6[0] == 0xfe && multicast6[1] == 0x80)
    prefer = PREFER_LINK;
  if (src6 == NULL) {
    i = _thc_ipv6_showerrors;
    if (multicast6 != NULL && multicast6[0] == 0xff && multicast6[1] == 0x02)
      _thc_ipv6_showerrors = 0;
    if ((src6 = thc_get_own_ipv6(interface, multicast6, prefer)) == NULL) {
      fprintf(stderr, "Error: no ipv6 address found for interface %s!\n", interface);
      exit(-1);
    }
    _thc_ipv6_showerrors = i;
  }
  if ((smac = thc_get_own_mac(interface)) == NULL) {
    fprintf(stderr, "Error: no mac address found for interface %s!\n", interface);
    exit(-1);
  }
  if (verbose)
    printf("Selected source address %s to scan %s\n", thc_ipv62notation(src6), ptr);
  if (argv[optind + 2] != NULL && argc >= optind + 3) {
    if (verbose > 1)
      printf("Resolving %s ...\n", argv[optind + 2]);
    router6 = thc_resolve6(argv[optind + 2]);
    do_router = 1;
    if (use_dmac)
      mac = dmac;
    else if ((mac = thc_get_mac(interface, src6, router6)) == NULL) {
      fprintf(stderr, "Error: could not resolve mac address for destination router %s\n", argv[optind + 2]);
      exit(-1);
    }
  }
  //strcat(string, thc_ipv62notation(src6));
  sprintf(string, "dst %s", thc_ipv62notation(src6));
  if (dump_all == 0) {
    if (synports[0] != -1 || udpports[0] != -1 || ackports[0] != -1) {
      strcat(string, " and ( icmp6 or ");
      if (udpports[0] != -1)
        strcat(string, "udp ");
      if (udpports[0] != -1 && (synports[0] != -1 || ackports[0] != -1))
         strcat(string, "or ");
      if (synports[0] != -1 || ackports[0] != -1)
        strcat(string, "tcp ");
      strcat(string, ")");
    } else
      strcat(string, " and icmp6");
  }
  
  if (multicast6 != NULL && (enumerate_mac || enumerate_dhcp) && input == NULL && multicast6[0] == 0xff) {
    fprintf(stderr, "Warning: -M/-D options make no sense for multicast addresses and are ignored for these\n");
    enumerate_dhcp = enumerate_mac = 0;
  }
  // make the sending buffer unique
  si = getpid() % 65536;
  sp = 1200 + si % 30000;
  sp2 = htons(sp);
  memset(vendid, 0, sizeof(vendid));
  memset(nets, 0, sizeof(nets));
  memset(buf2, 0, sizeof(buf2));
  buf2[0] = NXT_INVALID;
  buf2[1] = 1;
  for (i = 0; i < sizeof(buf) / 2; i++)
    memcpy(buf + i * 2, (char *) &si, 2);

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n", interface, string);
    exit(-1);
  }

  if (input != NULL)
    if ((in = fopen(input, "r")) == NULL) {
      fprintf(stderr, "Error: coult not open file %s\n", input);
      exit(-1);
    }

  if (output != NULL) {
    if ((out = fopen(output, "w")) == NULL) {
      fprintf(stderr, "Error: could not create output file %s\n", output);
      exit(-1);
    } else
      setvbuf(out, NULL, _IONBF, 0);    // dont buffer output to file - for immediate scripting
  }
  // cur_enum states: 0 = as-is, 2 = dhcp, 1 = mac, 3 = from-to
  // curr states: 0 = cmdline, 1.. = line no. in input file
  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);
  if (verbose) {
    timeval = time(NULL);
    printf("Starting alive6 %s (c) 2012 by van Hauser / THC at %s\n", VERSION, ctime(&timeval));
  }
  while (curr <= list) {
    ok = 1;
    if (cur_enum == 0) {
      if (curr == 0) {          // the command line target first - if present
        cur_dst = multicast6;
      } else {                  // input file processing, if present
        if (feof(in))
          curr++;
        line[0] = 0;
        ptr = fgets(line, sizeof(line), in);
        ptr = NULL;
        line[sizeof(line) - 1] = 0;
        j = strlen(line);
        if (j > 0)
          if (line[j - 1] == '\n')
            line[j - 1] = 0;
        if (j > 0)
          if (line[j - 1] == '\r')
            line[j - 1] = 0;
        if (j > 0) {
          ptr = line + j - 1;
          while (*ptr == ' ' || *ptr == '\t')
            *ptr-- = 0;
          ptr = line;
          while (*ptr == ' ' || *ptr == '\t')
            ptr++;
          if (*ptr == '#')
            ptr = NULL;
        } else
          ok = 0;
      }
      // from here for both target input options
      if (ptr != NULL && (index(ptr, '-') != NULL && index(ptr, '.') == NULL) && index(ptr, ':') != NULL)
        fromto = 1;
      else {
        if (ok && verbose > 1)
          printf("Resolving %s ...\n", ptr);
        if ((cur_dst = thc_resolve6(ptr)) == NULL) {
          if (ok)
            fprintf(stderr, "Warning: could not resolve %s, skipping\n", ptr);
          ok = 0;
        } else {
          memcpy(orig_dst, cur_dst, 16);
          if (enumerate_dhcp) {
            if ((local = thc_is_dst_local(interface, cur_dst)) > 0) {
              if (cur_dst[0] != 0xff)
                if ((p2 = thc_ipv62notation(cur_dst)) != NULL) {
                  fprintf(stderr, "Warning: enumeration on local address %s disabled, use ff02::1!\n", p2);
                  free(p2);
                }
            } else {
              i = 0;
              if (no_nets > 0)
                for (j = 0; j < no_nets; j++)
                  if (memcmp(nets[j], cur_dst, 8) == 0)
                    i = 1;
              if (i == 0) {
                cur_enum = 2;
                restart = 1;
                if (no_nets < MAX_NETS) {
                  memcpy(nets[no_nets], cur_dst, 8);
                  no_nets++;
                  if (no_nets == MAX_NETS)
                    fprintf(stderr, "Warning: more than %d networks found, disabling double network check!\n", MAX_VENDID);
                }
              } else {
                ok = 0;         // already scanned
              }
            }
          } else if (enumerate_mac && cur_dst[11] == 0xff && cur_dst[12] == 0xfe) {
            i = 0;
            if (no_vendid > 0)
              for (j = 0; j < no_vendid; j++)
                if (memcmp(vendid[j], cur_dst, 11) == 0)
                  i = 1;
            if (i == 0) {
              cur_enum = 1;
              restart = 1;
            }
          } else
            local = -1;
        }
      }
      if (fromto)
        cur_enum = 3;
      if (cur_enum == 0 && curr == 0)
        curr++;
    } else if (cur_enum == 1) {
      // enumeration of vendor-id keyspaces identified, lowest 3 bytes of ipv6
      if (restart) {
        restart = 0;
        bl = bm = bh = 0;
        memcpy(cur_dst, orig_dst, 16);
        memset(cur_dst + 13, 0, 3);
        if (verbose) {
          p2 = thc_ipv62notation(cur_dst);
          printf("Info: started autoconfiguration address space scan on %s\n", p2);
          free(p2);
        }
        if (no_vendid < MAX_VENDID) {
          memcpy(vendid[no_vendid], cur_dst, 11);
          no_vendid++;
          if (no_vendid == MAX_VENDID)
            fprintf(stderr, "Warning: more than %d vendor ids found, disabling double vendor id check!\n", MAX_VENDID);
        }
      } else {
        if (bl == 255) {
          bl = 0;
          if (bm == 255) {
            bm = 0;
            bh++;
            cur_dst[13] = bh;
          } else {
            bm++;
          }
          cur_dst[14] = bm;
        } else {
          bl++;
          if (bh == 255 && bm == 255 && bl == 255) {
            cur_enum = 0;
            if (curr == 0)
              curr++;
          }
        }
      }
      cur_dst[15] = bl;
    } else if (cur_enum == 2) {
      // enumeration of common dhcp6 address space,
      // using dict[] ranges, approx. 2000 addresses
      if (restart) {
        memcpy(cur_dst, orig_dst, 16);
        memset(cur_dst + 8, 0, 8);
        if (verbose) {
          p2 = thc_ipv62notation(cur_dst);
          printf("Info: started dhcp6 address space scan on %s\n", p2);
          free(p2);
        }
        restart = 0;
        ip1 = ip2 = ip3 = ip4 = 0;      // only because dict starts with 0
        dictptr = 0;
      } else {
        if (ip4 < dict[dictptr + 7])
          ip4++;
        else if (ip3 < dict[dictptr + 6]) {
          ip3++;
          ip4 = dict[dictptr + 3];
        } else if (ip2 < dict[dictptr + 5]) {
          ip2++;
          ip3 = dict[dictptr + 2];
          ip4 = dict[dictptr + 3];
        } else if (ip1 < dict[dictptr + 4]) {
          ip1++;
          ip2 = dict[dictptr + 1];
          ip3 = dict[dictptr + 2];
          ip4 = dict[dictptr + 3];
        } else {
          dictptr += 8;
          ip1 = dict[dictptr];
          ip2 = dict[dictptr + 1];
          ip3 = dict[dictptr + 2];
          ip4 = dict[dictptr + 3];
        }
        cur_dst[8] = ip1 / 256;
        cur_dst[9] = ip1 % 256;
        cur_dst[10] = ip2 / 256;
        cur_dst[11] = ip2 % 256;
        cur_dst[12] = ip3 / 256;
        cur_dst[13] = ip3 % 256;
        cur_dst[14] = ip4 / 256;
        cur_dst[15] = ip4 % 256;

        if (ip1 == ip2 && ip1 == ip3 && ip1 == ip4 && ip1 == 0xffff) {  // end of dict
          if (enumerate_mac && orig_dst[11] == 0xff && orig_dst[12] == 0xfe) {
            i = 0;
            if (no_vendid > 0)
              for (j = 0; j < no_vendid; j++)
                if (memcmp(vendid[j], orig_dst, 11) == 0)
                  i = 1;
            if (i == 0) {
              cur_enum = 1;
              restart = 1;
            } else
              cur_enum = 0;
          } else {
            cur_enum = 0;
          }
          if (curr == 0 && cur_enum == 0)
            curr++;
        }
      }
    }                           /*else */
    if (cur_enum == 3) {
      if (fromto) {
        fromto = 0;
        ok = 1;
        // init
        if (strlen(ptr) > 80) {
          ok = 0;
        } else {
          if (curr != 0) {
            memcpy(line2, line, 80);
            ptr = line2;
            line2[80] = 0;
          }
          memset(line, 0, 80);
          i = j = k = 0;
          while (i == 0) {
            while (ptr[k] != '-' && k < 80 && ptr[k] != 0)
              line[j++] = ptr[k++];
            if (ptr[k] == '-')
              while (ptr[k] != ':' && k < 80 && ptr[k] != 0)
                k++;
            if (ptr[k] != ':')
              i = 1;
          }
          if (verbose > 1)
            printf("Resolving %s ...\n", line);
//printf("ptr: %s, line %s, cur_dst %s, multicast6 %s\n", ptr, line, cur_dst, multicast6);
          if ((cur_dst = thc_resolve6(line)) == NULL) {
            ok = 0;
          } else {
            memset(line, 0, 80);
            j = k = strlen(ptr) - 1;
            while (i == 1) {
              while (ptr[k] != '-' && k >= 0 && ptr[k] != 0)
                line[j--] = ptr[k--];
              if (ptr[k] == '-')
                while (ptr[k] != ':' && k >= 0 && ptr[k] != 0)
                  k--;
              if (ptr[k] != ':')
                i = 0;
            }
          }
          ptr2 = &line[j + 1];
          if (verbose > 1)
            printf("Resolving %s ...\n", ptr2);
          if ((ptr3 = thc_resolve6(ptr2)) == NULL) {
            ok = 0;
          } else {
            cip1 = fip1 = (cur_dst[0] << 8) + (unsigned char) cur_dst[1];
            cip2 = fip2 = (cur_dst[2] << 8) + (unsigned char) cur_dst[3];
            cip3 = fip3 = (cur_dst[4] << 8) + (unsigned char) cur_dst[5];
            cip4 = fip4 = (cur_dst[6] << 8) + (unsigned char) cur_dst[7];
            cip5 = fip5 = (cur_dst[8] << 8) + (unsigned char) cur_dst[9];
            cip6 = fip6 = (cur_dst[10] << 8) + (unsigned char) cur_dst[11];
            cip7 = fip7 = (cur_dst[12] << 8) + (unsigned char) cur_dst[13];
            cip8 = fip8 = (cur_dst[14] << 8) + (unsigned char) cur_dst[15];
            tip1 = (ptr3[0] << 8) + (unsigned char) ptr3[1];
            tip2 = (ptr3[2] << 8) + (unsigned char) ptr3[3];
            tip3 = (ptr3[4] << 8) + (unsigned char) ptr3[5];
            tip4 = (ptr3[6] << 8) + (unsigned char) ptr3[7];
            tip5 = (ptr3[8] << 8) + (unsigned char) ptr3[9];
            tip6 = (ptr3[10] << 8) + (unsigned char) ptr3[11];
            tip7 = (ptr3[12] << 8) + (unsigned char) ptr3[13];
            tip8 = (ptr3[14] << 8) + (unsigned char) ptr3[15];
            if (fip1 > tip1 || fip2 > tip2 || fip3 > tip3 || fip4 > tip4 || fip5 > tip5 || fip6 > tip6 || fip7 > tip7 || fip8 > tip8)
              ok = 0;
            if (ok && verbose) {
              p2 = thc_ipv62notation(cur_dst);
              p3 = thc_ipv62notation(ptr3);
              printf("Info: started range address scan from %s to %s \n", p2, p3);
              free(p2);
              free(p3);
            }
            free(ptr3);
          }
        }
        if (ok) {
          memcpy(orig_dst, cur_dst, 16);
        } else {
          fprintf(stderr, "Error: range is invalid: %s, skipping\n", ptr);
          cur_enum = 0;
          if (curr == 0)
            curr++;
        }
      } else {
        if (cip8 < tip8)
          cip8++;
        else if (cip7 < tip7) {
          cip7++;
          cip8 = fip8;
        } else if (cip6 < tip6) {
          cip6++;
          cip7 = fip7;
          cip8 = fip8;
        } else if (cip5 < tip5) {
          cip5++;
          cip6 = fip6;
          cip7 = fip7;
          cip8 = fip8;
        } else if (cip4 < tip4) {
          cip4++;
          cip5 = fip5;
          cip6 = fip6;
          cip7 = fip7;
          cip8 = fip8;
        } else if (cip3 < tip3) {
          cip3++;
          cip4 = fip4;
          cip5 = fip5;
          cip6 = fip6;
          cip7 = fip7;
          cip8 = fip8;
        } else if (cip2 < tip2) {
          cip2++;
          cip3 = fip3;
          cip4 = fip4;
          cip5 = fip5;
          cip6 = fip6;
          cip7 = fip7;
          cip8 = fip8;
        } else if (cip1 < tip1) {
          cip1++;
          cip2 = fip2;
          cip3 = fip3;
          cip4 = fip4;
          cip5 = fip5;
          cip6 = fip6;
          cip7 = fip7;
          cip8 = fip8;
        } else
          ok = 0;

        cur_dst[0] = cip1 / 256;
        cur_dst[1] = cip1 % 256;
        cur_dst[2] = cip2 / 256;
        cur_dst[3] = cip2 % 256;
        cur_dst[4] = cip3 / 256;
        cur_dst[5] = cip3 % 256;
        cur_dst[6] = cip4 / 256;
        cur_dst[7] = cip4 % 256;
        cur_dst[8] = cip5 / 256;
        cur_dst[9] = cip5 % 256;
        cur_dst[10] = cip6 / 256;
        cur_dst[11] = cip6 % 256;
        cur_dst[12] = cip7 / 256;
        cur_dst[13] = cip7 % 256;
        cur_dst[14] = cip8 / 256;
        cur_dst[15] = cip8 % 256;

        if (ok == 0) {
          cur_enum = 0;
          if (enumerate_dhcp) {
            if ((local = thc_is_dst_local(interface, cur_dst)) > 0) {
              if (cur_dst[0] != 0xff) {
                p2 = thc_ipv62notation(orig_dst);
                fprintf(stderr, "Warning: enumeration on local address %s disabled, use ff02::1!\n", p2);
                free(p2);
              }
            } else {
              i = 0;
              if (no_nets > 0)
                for (j = 0; j < no_nets; j++)
                  if (memcmp(nets[j], cur_dst, 8) == 0)
                    i = 1;
              if (i == 0) {
                cur_enum = 2;
                restart = 1;
                if (no_nets < MAX_NETS) {
                  memcpy(nets[no_nets], cur_dst, 8);
                  no_nets++;
                  if (no_nets == MAX_NETS)
                    fprintf(stderr, "Warning: more than %d networks found, disabling double network check!\n", MAX_VENDID);
                }
              } else {
                ok = 0;         // already scanned
              }
            }
          } else if (enumerate_mac && orig_dst[11] == 0xff && orig_dst[12] == 0xfe) {
            i = 0;
            if (no_vendid > 0)
              for (j = 0; j < no_vendid; j++)
                if (memcmp(vendid[j], cur_dst, 11) == 0)
                  i = 1;
            if (i == 0) {
              cur_enum = 1;
              restart = 1;
            }
          } else {
            local = -1;
            cur_enum = 0;
          }
          if (curr == 0)
            curr++;
        }
      }
    }
    if (cur_enum > 3) {
      fprintf(stderr, "Error: WTF?!\n");
      exit(-1);
    }
    // here we send the alive check packets - if we have a valid destination
    if (do_router) {
      routers[0] = cur_dst;
      routers[1] = NULL;
      cur_dst = router6;        // switch destination and router
    }
    // central dst mac lookup and fast/slow implementation
    no_send = no_send_local;
    if (ok && rawmode == 0 && cur_dst != NULL && do_router == 0 && use_dmac == 0) {
      if (local == -1)
        local = thc_is_dst_local(interface, cur_dst);
      if (local == 0 && slow == 0) {
        if (rmac == NULL)
          rmac = thc_get_mac(interface, src6, cur_dst);
        mac = rmac;
      }
      if (local == 1 || slow)
        mac = thc_get_mac(interface, src6, cur_dst);
      if (local && mac != NULL && slow == 0 && cur_dst[0] != 0xff) {
        // if a local system has an ARP entry, assume its alive if the slow
        // mode is not set. so if proxy NA is present, use -S
        if (resolve)
          he = gethostbyaddr(cur_dst, 16, AF_INET6);
        p2 = thc_ipv62notation(cur_dst);
        printf("Alive: %s%s%s%s [NDP]\n", p2, resolve ? " (" : "", resolve && he != NULL ? he->h_name : "", resolve ? ")" : "");
        if (out != NULL)
          fprintf(out, "%s%s%s%s\n", p2, resolve ? " (" : "", (resolve && he != NULL) ? he->h_name : "", resolve ? ")" : "");
        free(p2);
        if (alive_no < MAX_ALIVE && (alive[alive_no] = malloc(16)) != NULL) {
          memcpy(alive[alive_no], cur_dst, 16);
          alive_no++;
          if (alive_no == MAX_ALIVE)
            fprintf(stderr, "Warning: more than %d alive systems detected, disabling double results check!\n", MAX_ALIVE);
        }
        tcount++;
        ok = 0;
      }
      if (mac == NULL) {
        p2 = thc_ipv62notation(cur_dst);
        fprintf(stderr, "Error: Can not resolve mac address for %s\n", p2);
        free(p2);
        ok = 0;
      }
    }
    if (use_dmac)
      mac = dmac;
    else if (local == 0)
      no_send = no_send_remote;

    if (ok && cur_dst != NULL) {
      if (debug)
        printf("DEBUG: sending alive check packets to %s\n", thc_ipv62notation(cur_dst));
      else if (verbose > 2) {
        p2 = thc_ipv62notation(cur_dst);
        printf("Testing %s ...\n", p2);
        free(p2);
      }
      for (nos = 0; nos < no_send; nos++) {     // send -n defined times, default: 1
        if (do_ping) {
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe, (unsigned char *) &buf, sizeof(buf), 0) < 0)
            return -1;
          if (thc_generate_pkt(interface, smac, mac, pkt, &pkt_len) < 0) {
            fprintf(stderr, "Error: Can not send packet, exiting ...\n");
            exit(-1);
          }
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset,
                                  hdr->pkt_len > 1240 ? 1240 : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
          } else
            while (thc_send_pkt(interface, pkt, &pkt_len) < 0)
              usleep(1);
          pkt = thc_destroy_packet(pkt);
          if (waittime)
            usleep(waittime);
        }
        if (do_dst) {
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_hdr_dst(pkt, &pkt_len, (unsigned char *) &buf2, sizeof(buf2)) < 0)
            return -1;
          if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe, (unsigned char *) &buf, sizeof(buf), 0) < 0)
            return -1;
          thc_generate_pkt(interface, smac, mac, pkt, &pkt_len);
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset,
                                  hdr->pkt_len > 1240 ? 1240 : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
          } else
            while(thc_send_pkt(interface, pkt, &pkt_len) < 0)
              usleep(1);
          pkt = thc_destroy_packet(pkt);
          if (waittime)
            usleep(waittime);
        }
        if (do_hop) {
          if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
            return -1;
          if (router6 != NULL)
            if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
              return -1;
          if (thc_add_hdr_hopbyhop(pkt, &pkt_len, (unsigned char *) &buf2, sizeof(buf2)) < 0)
            return -1;
          if (thc_add_icmp6(pkt, &pkt_len, ICMP6_PINGREQUEST, 0, 0xfacebabe, (unsigned char *) &buf, sizeof(buf), 0) < 0)
            return -1;
          thc_generate_pkt(interface, smac, mac, pkt, &pkt_len);
          if (router6 != NULL) {
            hdr = (thc_ipv6_hdr *) pkt;
            thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset,
                                  hdr->pkt_len > 1240 ? 1240 : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
          } else
            while(thc_send_pkt(interface, pkt, &pkt_len) < 0)
              usleep(1);
          pkt = thc_destroy_packet(pkt);
          if (waittime)
            usleep(waittime);
        }
        if (udpports[0] != -1) {
          i = 0;
          while (udpports[i] != -1 && i < MAX_PORTS) {
            if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
              return -1;
            if (router6 != NULL)
              if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
                return -1;
            if (thc_add_udp(pkt, &pkt_len, sp, udpports[i] % 65536, 0, dns6buf, sizeof(dns6buf)) < 0)
              return -1;
            if (thc_generate_pkt(interface, smac, mac, pkt, &pkt_len) < 0) {
              fprintf(stderr, "Error: Can not send packet, exiting ...\n");
              exit(-1);
            }
            if (router6 != NULL) {
              hdr = (thc_ipv6_hdr *) pkt;
              thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset,
                                    hdr->pkt_len > 1240 ? 1240 : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
            } else
              while(thc_send_pkt(interface, pkt, &pkt_len) < 0)
              usleep(1);
            pkt = thc_destroy_packet(pkt);
            if (waittime)
              usleep(waittime);
            i++;
          }
        }
        if (synports[0] != -1) {
          i = 0;
          while (synports[i] != -1 && i < MAX_PORTS) {
            if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
              return -1;
            if (router6 != NULL)
              if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
                return -1;
            if (thc_add_tcp(pkt, &pkt_len, sp, synports[i] % 65536, (sp << 16) + sp, 0, TCP_SYN, 5760, 0, NULL, 0, NULL, 0) < 0)
              return -1;
            if (thc_generate_pkt(interface, smac, mac, pkt, &pkt_len) < 0) {
              fprintf(stderr, "Error: Can not send packet, exiting ...\n");
              exit(-1);
            }
            if (router6 != NULL) {
              hdr = (thc_ipv6_hdr *) pkt;
              thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset,
                                    hdr->pkt_len > 1240 ? 1240 : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
            } else
              while(thc_send_pkt(interface, pkt, &pkt_len) < 0)
                usleep(1);
            pkt = thc_destroy_packet(pkt);
            if (waittime)
              usleep(waittime);
            i++;
          }
        }
        if (ackports[0] != -1) {
          i = 0;
          while (ackports[i] != -1 && i < MAX_PORTS) {
            if ((pkt = thc_create_ipv6(interface, prefer, &pkt_len, src6, cur_dst, 0, 0, 0, 0, 0)) == NULL)
              return -1;
            if (router6 != NULL)
              if (thc_add_hdr_route(pkt, &pkt_len, routers, 1) < 0)
                return -1;
            if (thc_add_tcp(pkt, &pkt_len, sp, ackports[i] % 65536, (sp << 16) + sp, (sp << 16) + sp, TCP_ACK, 5760, 0, NULL, 0, NULL, 0) < 0)
              return -1;
            if (thc_generate_pkt(interface, smac, mac, pkt, &pkt_len) < 0) {
              fprintf(stderr, "Error: Can not send packet, exiting ...\n");
              exit(-1);
            }
            if (router6 != NULL) {
              hdr = (thc_ipv6_hdr *) pkt;
              thc_send_as_fragment6(interface, src6, cur_dst, NXT_ROUTE, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset,
                                    hdr->pkt_len > 1240 ? 1240 : (((hdr->pkt_len - 40 - offset) / 16) + 1) * 8);
            } else
              while(thc_send_pkt(interface, pkt, &pkt_len) < 0)
                usleep(1);
            pkt = thc_destroy_packet(pkt);
            if (waittime)
              usleep(waittime);
            i++;
          }
        }
      }

      tcount++;
      if (do_router)
        cur_dst = router6;      // switch back

      // cleanup
      if (cur_enum == 0 && cur_dst != multicast6)
        free(cur_dst);

      if (cur_enum == 0 || cur_dst[15] == 0xff || tcount % 16 == 0)
        while (thc_pcap_check(p, (char *) check_packets, NULL) > 0);
    }
    if (mac != NULL && mac != rmac && use_dmac == 0) {
      free(mac);
      mac = NULL;
    }
  }

//  sleep(1);
  while (thc_pcap_check(p, (char *) check_packets, NULL) > 0);
  if (curr > 1 || ok || tcount > alive_no) {
    passed = time(NULL);
    do {
      thc_pcap_check(p, (char *) check_packets, NULL);
    } while (passed + 5 >= time(NULL) && ((tcount > alive_no && (tcount > 1 || alive_no == 0 || curr > 1)) || (multicast6 != NULL && multicast6[0] == 0xff)));
  }
  while (thc_pcap_check(p, (char *) check_packets, NULL) > 0);
  thc_pcap_close(p);
  if (out != NULL)
    fclose(out);
  printf("\nScanned %lu address%s and found %d system%s alive\n", tcount, tcount == 1 ? "" : "es", alive_no, alive_no == 1 ? "" : "s");
  if (verbose) {
    timeval = time(NULL);
    printf("Completed alive6 scan at %s\n", ctime(&timeval));
  }
  if (alive_no)
    return 0;
  else
    return 1;
}
