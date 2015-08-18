/*
    Copyright (c) warlord @ nologin.org.  All rights reserved.
    For more information, please visit http://www.nologin.org

    Fingerprinting technique originally provided by optyx
 */

#include "thc-ipv6.h"
#include "fps.h"

#define FPS_INVALID "invalid packet data"
#define FPS_UNKNOWN "unknown"
#define FPSFILE "/usr/local/etc/fps.txt"

static char _fingerprint[4096]; // not thread safe!
struct fingerprints_array fingerprints[1000];

/***********************************************************/

//Read the fingerprints from a file into an array
void read_FPs() {
  char *FP, *OS;
  char line[1024];              //should be enough imho
  int i = 0;
  FILE *file;

  memset(fingerprints, 0, sizeof(fingerprints));

  if ((file = fopen(FPSFILE, "r")) != NULL) {
    while (!feof(file)) {
      memset(line, 0, sizeof(line));
      fgets(line, sizeof(line) - 2, file);

      if ((strlen(line) == 1) || (strlen(line) == 0))
        continue;

      line[strlen(line) - 1] = 0;

      FP = strtok(line, "|");
      OS = strtok(NULL, "\n");
      if ((OS == NULL) || (FP == NULL)) {
        printf("Error reading fingerprints file at line %d\n", i);
        printf("Read:  OS: %s - Fingerprint: %s\n", OS, FP);
        exit(1);;
      }

      snprintf(fingerprints[i].OS, sizeof(fingerprints[i].OS), "%s", OS);
      memcpy(fingerprints[i].fingerprint, FP, sizeof(fingerprints[i].fingerprint) - 2);
      i++;
    }
    fclose(file);
  } else {
    printf("\n---> Failed to open %s. Using internal fingerprints instead.\n\n", FPSFILE);
  }

  return;
}


/***********************************************************/
//Supply a fingerprint, get to know what OS it is

char *get_OS(char *query_fp) {
  int i = 0;

  do {
    if (strcmp(fingerprints[i].fingerprint, query_fp) == 0) {
      return fingerprints[i].OS;
    }
    i++;
  }
  while (strlen(fingerprints[i].fingerprint) > 0);

  for (i = 0; i < sizeof(fingerprintsArray) / sizeof(fingerprintsArray[0]); i++) {
    if (strcmp(fingerprintsArray[i].fingerprint, query_fp) == 0)
      return fingerprintsArray[i].OS;
  }

  return FPS_UNKNOWN;
}


/***********************************************************/

char *checkFingerprint(char *buffer, int len) {
  char *os, *end, *ptr, ip_ver = 0, ip_hdr_size = 0;

  ip_ver = (((unsigned char) buffer[0] & 0xf0) >> 4);

  if (ip_ver == 4) {
    ip_hdr_size = ((buffer[0] & 0x0f) << 2);
  } else if (ip_ver == 6) {
    ip_hdr_size = 40;
  } else
    return FPS_INVALID;

  if (ip_ver == 0 || (len - ip_hdr_size) < 20 || ip_hdr_size < 20 || ip_hdr_size > 60)  // invalid ip version or packet too short?
    return FPS_INVALID;

  snprintf(_fingerprint, sizeof(_fingerprint) - 1, "%04x:%02x:%04x", len + 20 - ip_hdr_size,    // total length (calculated with assumed ipv4 header
           (unsigned char) buffer[ip_hdr_size + 12],    // tcp header length(and flags)
           ntohs(*(in_port_t *) & buffer[ip_hdr_size + 14]));   // window size

  //So what kind of tcp options did we receive?
  //This is being used for OS fingerprinting
  end = &buffer[len];

  if (len > ip_hdr_size + (unsigned char) buffer[ip_hdr_size + 12])
    end = &buffer[ip_hdr_size + (unsigned char) buffer[ip_hdr_size + 12]];

  for (ptr = &buffer[ip_hdr_size + 20]; ptr < end;) {
    switch (*ptr) {
    case 0x0:                  // end of options
      ptr = end;
      break;
    case 0x1:                  // some pad entire options portion with NOP to keep response option size the same
      strncat(_fingerprint, ":NOP", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
      ptr++;
      break;
    case 0x2:                  // segment size
      snprintf(&_fingerprint[strlen(_fingerprint)], sizeof(_fingerprint) - strlen(_fingerprint), ":SS%04x", ntohs(*(in_port_t *) (ptr + 2)));
      ptr += 4;
      break;
    case 0x3:                  // window scaling
      strncat(_fingerprint, ":WSxx", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
      ptr += 3;
      break;
    case 0x4:                  // Sack Permitted / Sack Denied
      switch (ptr[1]) {
      case 0x2:
        strncat(_fingerprint, ":SP", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
        break;
      default:
        strncat(_fingerprint, ":SD", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
        break;
      }
      ptr += 2;
      break;
    case 0x6:                  // echo request
      strncat(_fingerprint, ":PI", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
      ptr += 6;
      break;
    case 0x7:                  // echo reply
      strncat(_fingerprint, ":PO", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
      ptr += 6;
      break;
    case 0x8:                  // Time stamp
      strncat(_fingerprint, ":TS", sizeof(_fingerprint) - strlen(_fingerprint) - 1);
      ptr += 10;
      break;
    default:                   // unknown
      snprintf(&_fingerprint[strlen(_fingerprint)], sizeof(_fingerprint) - strlen(_fingerprint), ":UOP%02x", (unsigned char) (*ptr));
      ptr += (unsigned char) ptr[1];
      break;
    }
  }

  _fingerprint[sizeof(_fingerprint) - 1] = 0;
  os = get_OS(_fingerprint);

  if (strcmp(os, FPS_UNKNOWN) == 0)
    return _fingerprint;

  return os;
}
