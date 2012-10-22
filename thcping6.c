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
#include <sys/timeb.h>
#include <ctype.h>
#include "thc-ipv6.h"

struct timespec ts, ts2;
int dlen = 8, port = 0, done = 0, resp_type = -1, type = NXT_ICMP6;

extern int do_pppoe;
extern int do_hdr_off;
extern int do_6in4;
extern int do_hdr_vlan;

void help(char *prg) {
  printf("%s %s (c) 2012 by %s %s\n\n", prg, VERSION, AUTHOR, RESOURCE);
  printf("Syntax: %s [-af] [-H o:s:v] [-D o:s:v] [-F dst] [-t ttl] [-c class] [-l label] [-d size] [-S port|-U port] interface src6 dst6 [srcmac [dstmac [data]]]\n\n", prg);
  printf("Craft your special icmpv6 echo request packet.\n");
  printf("You can put an \"x\" into src6, srcmac and dstmac for an automatic value.\n");
  printf("Options:\n");
  printf("  -a              add a hop-by-hop header with router alert option.\n");
  printf("  -q              add a hop-by-hop header with quickstart option.\n");
  printf("  -E              send as ethertype IPv4\n");
  printf("  -H o:s:v        add a hop-by-hop header with special content\n");
  printf("  -D o:s:v        add a destination header with special content\n");
  printf("  -D \"xxx\"        add a large destination header which fragments the packet\n");
  printf("  -f              add a one-shot fragementation header\n");
  printf("  -F ipv6address  use source routing to this final destination\n");
  printf("  -t ttl          specify TTL (default: 64)\n");
  printf("  -c class        specify a class (0-4095)\n");
  printf("  -l label        specify a label (0-1048575)\n");
  printf("  -d data_size    define the size of the ping data buffer\n");
  printf("  -S port         use a TCP SYN packet on the defined port instead of ping\n");
  printf("  -U port         use a UDP packet on the defined port instead of ping\n");
  printf("o:s:v syntax: option-no:size:value, value is in hex, e.g. 1:2:feab\n");
  printf("Returns -1 on error or no reply, 0 on normal reply or 1 on error reply.\n");
  exit(-1);
}

void alarming() {
  if (done == 0)
    printf("No packet received, terminating.\n");
  exit(resp_type);
}

void check_packets(u_char *pingdata, const struct pcap_pkthdr *header, const unsigned char *data) {
  int len = header->caplen - 14, min = 0, usec, ok = 0, nxt = 6, offset = 0;
  unsigned int mtu = 0;
  unsigned char *ptr = (unsigned char *) (data + 14), *frag = "";
  
  if (do_hdr_size) {
    ptr = (unsigned char*) (data + do_hdr_size);
    len = (header->caplen - do_hdr_size);
    if ((ptr[0] & 240) != 0x60)
      return; 
  }

  clock_gettime(CLOCK_REALTIME, &ts2);
  if (ts2.tv_nsec < ts.tv_nsec) {
    min = 1;
    usec = (int) ((1000000000 - ts.tv_nsec + ts2.tv_nsec) / 10000);
  } else
    usec = (int) ((ts2.tv_nsec - ts.tv_nsec) / 10000);
  if (ptr[nxt] == NXT_FRAG) {
    offset += 8;
    nxt = 40;
    frag = " (fragmented)";
  }
  if (ptr[nxt] == NXT_ICMP6) {
    if (len < 44 + offset || ((len + 44 + offset) < dlen && dlen < 1000) || (len  + offset < 986 && dlen > 900)) {
      if (debug)
        printf("ignoring too short packet\n");
      return;
    }
    if (dlen < 1000) {
      if (memcmp(pingdata, ptr + len - dlen, dlen) == 0)
        ok = 1;
    } else {
      if (memcmp(pingdata, ptr + 256 + offset, 100) == 0 || memcmp(pingdata, ptr + 260, 100) == 0 || memcmp(pingdata, ptr + 242, 100) == 0 || memcmp(pingdata, data + 260 + offset, 100) == 0)
        ok = 1;
    }
    if (ok) {
      printf("%04u.%04u \t", (int) (ts2.tv_sec - ts.tv_sec - min), usec);
      switch (ptr[40 + offset]) {
      case ICMP6_PINGREPLY:
        printf("pong");
        resp_type = 0;
        break;
      case ICMP6_PARAMPROB:
        printf("icmp parameter problem type %d", ptr[41 + offset]);
        resp_type = 1;
        break;
      case ICMP6_REDIR:
        printf("icmp redirect");
        break;
      case ICMP6_UNREACH:
        printf("icmp unreachable type %d", ptr[41 + offset]);
        resp_type = 1;
        break;
      case ICMP6_TOOBIG:
        mtu = (ptr[44 + offset] << 24) + (ptr[45 + offset] << 16) + (ptr[46 + offset] << 8) + ptr[47 + offset];
        printf("icmp too big (max mtu: %d)", mtu);
        resp_type = 1;
        break;
      case ICMP6_TTLEXEED:
        printf("icmp ttl exceeded");
        resp_type = 1;
        break;
//      default:
        // ignored
        //printf("icmp6 %d:%d", ptr[40 + offset], ptr[41 + offset]);
        //resp_type = 1;
      }
    } else
      printf("(ignoring icmp6 packet with different contents (proto %d, type %d, code %d)) ", ptr[nxt], ptr[40 + offset], ptr[41 + offset]);
  } else {
    if (type == NXT_TCP) {
      printf("%04u.%04u \ttcp-", (int) (ts2.tv_sec - ts.tv_sec - min), usec);
      switch((ptr[53 + offset] % 8)) {
        case 2:
          printf("syn-ack");
          resp_type = 0;
          break;
        case 4:
          printf("rst");
          resp_type = 1;
          break;
        default:
          printf("illegal");
          resp_type = 1;
          break;
      }
    } else
      printf("%04u.%04u \tudp", (int) (ts2.tv_sec - ts.tv_sec - min), usec);
  }
  printf("%s packet received from %s\n", frag, thc_ipv62notation(ptr + 8));
  if (done == 0 && resp_type >= 0) {
    alarm(2);
    done = 1;
  }
}

int main(int argc, char *argv[]) {
  unsigned char *pkt1 = NULL, buf[2096] = "thcping6", *routers[2], buf2[1300];
  unsigned char *src6 = NULL, *dst6 = NULL, smac[16] = "", dmac[16] = "", *srcmac = smac, *dstmac = dmac;
  char string[255] = "ip6 and dst ", *interface, *d_opt = NULL, *h_opt = NULL, *oo, *ol, *ov;
  int pkt1_len = 0, flags = 0, frag = 0, alert = 0, quick = 0, route = 0, ttl = 64, label = 0, class = 0, i, j, ether = 0, xl = 0, frag_type = NXT_DST, offset = 14;
  pcap_t *p;
  thc_ipv6_hdr *hdr;

  setvbuf(stdout, NULL, _IONBF, 0);
  setvbuf(stderr, NULL, _IONBF, 0);

  memset(buf, 0, sizeof(buf));
  while ((i = getopt(argc, argv, "aqfd:D:H:F:t:c:l:S:U:EX")) >= 0) {
    switch (i) {
    case 'X':
      debug = 1;
      break;
    case 'a':
      alert = 1;
      break;
    case 'q':
      quick = 1;
      break;
    case 'f':
      frag = 1;
      break;
    case 'E':
      ether = 1;
      break;
    case 'F':
      route = 1;
      if ((routers[0] = thc_resolve6(optarg)) == NULL) {
        fprintf(stderr, "Error: %s does not resolve to a valid IPv6 address\n", optarg);
        exit(-1);
      }
      routers[1] = NULL;
      break;
    case 'S':
      port = atoi(optarg);
      type = NXT_TCP;
      break;
    case 'U':
      port = atoi(optarg);
      type = NXT_UDP;
      break;
    case 'D':
      d_opt = optarg;
      break;
    case 'H':
      h_opt = optarg;
      break;
    case 't':
      ttl = atoi(optarg);
      break;
    case 'c':
      class = atoi(optarg);
      break;
    case 'l':
      label = atoi(optarg);
      break;
    case 'd':
      dlen = atoi(optarg);
      if (dlen > 2096)
        dlen = 2096;
      for (j = 0; j < (dlen / 8); j++)
        memcpy(buf + j * 8, "thcping6", 8);
      break;
    default:
      fprintf(stderr, "Error: invalid option %c\n", i);
      exit(-1);
    }
  }

  if (argc - optind < 2)
    help(argv[0]);

  if (do_hdr_size)
    offset = do_hdr_size;
  interface = argv[optind];
  if (argc - optind == 2) {
    dst6 = thc_resolve6(argv[optind + 1]);
    if ((src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL)) == NULL) {
      fprintf(stderr, "Error: no ipv6 address found for interface %s!\n", interface);
      exit(-1);
    }
  } else {
    dst6 = thc_resolve6(argv[optind + 2]);
    if (strcmp(argv[optind + 1], "x") != 0)
      src6 = thc_resolve6(argv[optind + 1]);
    else if ((src6 = thc_get_own_ipv6(interface, dst6, PREFER_GLOBAL)) == NULL) {
      fprintf(stderr, "Error: no ipv6 address found for interface %s!\n", interface);
      exit(-1);
    }
  }
  
  if (argc - optind >= 4) {
    if (strcmp(argv[optind + 3], "x") != 0)
      sscanf(argv[optind + 3], "%x:%x:%x:%x:%x:%x", (unsigned int *) &smac[0], (unsigned int *) &smac[1], (unsigned int *) &smac[2], (unsigned int *) &smac[3],
             (unsigned int *) &smac[4], (unsigned int *) &smac[5]);
    else
      srcmac = NULL;
  } else
    srcmac = NULL;
  if (argc - optind >= 5) {
    if (strcmp(argv[optind + 4], "x") != 0)
      sscanf(argv[optind + 4], "%x:%x:%x:%x:%x:%x", (unsigned int *) &dmac[0], (unsigned int *) &dmac[1], (unsigned int *) &dmac[2], (unsigned int *) &dmac[3],
             (unsigned int *) &dmac[4], (unsigned int *) &dmac[5]);
    else
      dstmac = NULL;
  } else
    dstmac = NULL;

  if ((pkt1 = thc_create_ipv6(interface, PREFER_GLOBAL, &pkt1_len, src6, dst6, ttl, 0, label, class, 0)) == NULL)
    return -1;
  if (alert || quick) {
    j = 0;
    memset(buf2, 0, sizeof(buf2));
    if (alert) {
      buf2[0] = 5;
      buf2[1] = 2;
      j = 4;
    }
    if (quick) {
      buf2[j] = 38;
      buf2[j+1] = 6;
      buf2[j+3] = 255;
      j += 8;
    }
    while ((j + 2) % 8 != 0)
      j++;
    if (thc_add_hdr_hopbyhop(pkt1, &pkt1_len, buf2, j) < 0)
      return -1;
    frag_type = NXT_HBH;
  }
  if (h_opt != NULL) {
    memset(buf2, 0, sizeof(buf2));
    frag_type = NXT_HBH;
    oo = h_opt;
    if ((ol = index(oo, ':')) == NULL) {
      fprintf(stderr, "Error: option value  must be optionnumber:length:value, e.g. 1:2:feab -> %s\n", h_opt);
      exit(-1);
    }
    *ol++ = 0;
    if ((ov = index(ol, ':')) == NULL) {
      fprintf(stderr, "Error: option value must be optionnumber:length:value, e.g. 1:2:feab -> %s\n", h_opt);
      exit(-1);
    }
    *ov++ = 0;
    buf2[0] = (atoi(oo)) % 256;
    buf2[1] = (atoi(ol)) % 256;
    if (*ov != 0)
      for (i = 0; i < strlen(ov) / 2; i++) {
        if (tolower(ov[i * 2]) >= 'a' && tolower(ov[i * 2]) <= 'f')
          j = (ov[i * 2] - 'a' + 10) * 16;
        else if (ov[i * 2] >= '0' && ov[i * 2] <= '9')
          j = (ov[i * 2] - '0') * 16;
        else {
          fprintf(stderr, "Error: only hexadecimal characters are allowed in value: %s\n", ov);
          exit(-1);
        }
        if (tolower(ov[i * 2 + 1]) >= 'a' && tolower(ov[i * 2 + 1]) <= 'f')
          j += (ov[i * 2 + 1] - 'a' + 10);
        else if (ov[i * 2 + 1] >= '0' && ov[i * 2 + 1] <= '9')
          j += (ov[i * 2 + 1] - '0');
        else {
          fprintf(stderr, "Error: only hexadecimal characters are allowed in value: %s\n", ov);
          exit(-1);
        }
        buf2[2 + i] = j % 256;
      }
    if (thc_add_hdr_hopbyhop(pkt1, &pkt1_len, buf2, 2 + (atoi(ol) % 256)) < 0)
      return -1;
  }
  if (frag) {
    if (thc_add_hdr_oneshotfragment(pkt1, &pkt1_len, getpid()) < 0)
      return -1;
    if (frag_type == NXT_DST)
      frag_type = NXT_FRAG;
  }
  if (route) {
    if (thc_add_hdr_route(pkt1, &pkt1_len, routers, 1) < 0)
      return -1;
    if (frag_type == NXT_DST)
      frag_type = NXT_ROUTE;
  }
  if (d_opt != NULL) {
    memset(buf2, 0, sizeof(buf2));
    if (d_opt[0] == 'x') {
      xl = 1;
      if (thc_add_hdr_dst(pkt1, &pkt1_len, buf2, sizeof(buf2)) < 0)
        return -1;
    } else {
      oo = d_opt;
      if ((ol = index(oo, ':')) == NULL) {
        fprintf(stderr, "Error: option value must be optionnumber:length:value, e.g. 1:2:feab: %s\n", h_opt);
        exit(-1);
      }
      *ol++ = 0;
      if ((ov = index(ol, ':')) == NULL) {
        fprintf(stderr, "Error: option value must be optionnumber:length:value, e.g. 1:2:feab: %s\n", h_opt);
        exit(-1);
      }
      *ov++ = 0;
      buf2[0] = (atoi(oo)) % 256;
      buf2[1] = (atoi(ol)) % 256;
      if (*ov != 0)
        for (i = 0; i < strlen(ov) / 2; i++) {
          if (tolower(ov[i * 2]) >= 'a' && tolower(ov[i * 2]) <= 'f')
            j = (ov[i * 2] - 'a' + 10) * 16;
          else if (ov[i * 2] >= '0' && ov[i * 2] <= '9')
            j = (ov[i * 2] - '0') * 16;
          else {
            fprintf(stderr, "Error: only hexadecimal characters are allowed in value: %s\n", ov);
            exit(-1);
          }
          if (tolower(ov[i * 2 + 1]) >= 'a' && tolower(ov[i * 2 + 1]) <= 'f')
            j += (ov[i * 2 + 1] - 'a' + 10);
          else if (ov[i * 2 + 1] >= '0' && ov[i * 2 + 1] <= '9')
            j += (ov[i * 2 + 1] - '0');
          else {
            fprintf(stderr, "Error: only hexadecimal characters are allowed in value: %s\n", ov);
            exit(-1);
          }
          buf2[2 + i] = j % 256;
        }
      if (thc_add_hdr_dst(pkt1, &pkt1_len, buf2, 2 + (atoi(ol) % 256)) < 0)
        return -1;
    }
  }
  if (argc - optind >= 6) {
    if (dlen != 8) {
      fprintf(stderr, "Warning: the data option is ignored if the -d option is supplied\n");
    } else {
      dlen = strlen(argv[optind + 5]);
      if (dlen > sizeof(buf))
        dlen = sizeof(buf) - 1;
      memcpy(buf, argv[optind + 5], dlen);
      buf[dlen] = 0;
    }
  }
  if (port == 0) {
    if (thc_add_icmp6(pkt1, &pkt1_len, ICMP6_ECHOREQUEST, 0, flags, (unsigned char *) &buf, dlen, 0) < 0)
      return -1;
  } else
    if (type == NXT_TCP) {
      if (thc_add_tcp(pkt1, &pkt1_len, 65534, port, (port << 16) + port, 0, TCP_SYN, 5760, 0, NULL, 0, NULL, 0) < 0)
        return -1;
    } else
      if (thc_add_udp(pkt1, &pkt1_len, 65534, port, 0, NULL, 0) < 0)
        return -1;
    
  if (thc_generate_pkt(interface, srcmac, dstmac, pkt1, &pkt1_len) < 0) {
    fprintf(stderr, "Error: Can not generate packet, exiting ...\n");
    exit(-1);
  }
  
  hdr = (thc_ipv6_hdr *) pkt1;
  
  if (ether) {
    if (do_hdr_size) {
      if (do_pppoe) {
        hdr->pkt[20 + do_hdr_off] = 0;    // PPP protocol value for IPv4
        hdr->pkt[21 + do_hdr_off] = 0x21;
      } else if (do_hdr_vlan && do_6in4 == 0) {
        hdr->pkt[16] = 8; // ethernet protocol value for IPv4
        hdr->pkt[17] = 0;
      } else
        fprintf(stderr, "Warning: ether option does not work with 6in4 injection\n");
    } else {
      hdr->pkt[12] = 8; // ethernet protocol value for IPv4
      hdr->pkt[13] = 0;
    }
  }

  strcat(string, thc_ipv62notation(src6));

  signal(SIGALRM, alarming);
  alarm(6);

  if ((p = thc_pcap_init(interface, string)) == NULL) {
    fprintf(stderr, "Error: could not capture on interface %s with string %s\n", interface, string);
    exit(-1);
  }

  if (xl)
    thc_send_as_fragment6(interface, src6, dst6, frag_type, hdr->pkt + 40 + offset, hdr->pkt_len - 40 - offset, 1280);
  else
    while (thc_send_pkt(interface, pkt1, &pkt1_len) < 0)
      usleep(1);
  clock_gettime(CLOCK_REALTIME, &ts);
  printf("0000.0000 \t%s packet sent to %s\n", port == 0 ? "ping" : type == NXT_TCP ? "tcp-syn" : "udp", thc_ipv62notation(dst6));
  while (1) {
    thc_pcap_check(p, (char *) check_packets, buf);
  }

  return resp_type;                     // not reached
}
