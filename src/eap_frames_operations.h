#ifndef EAP_FRAMES_OPERATIONS_
#define EAP_FRAMES_OPERATIONS_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "construct_eap_frames.h"
#include "functions.h"

#define DEBUG 1

typedef enum {
  EAPOL_START = 0,
  EAP_REQUEST_IDENTITY,
  EAP_REQUEST_MD5_CHALLENGE,
  EAPOL_LOGOFF,
  EAP_FAILURE,
  EAP_SUCCESS,
  ONLINE,

  ERROR
} SEND_FRAME_TYPE;

const static unsigned SNAP_LENGTH = 2048; // snapshot length
//const static unsigned EAP_ID_ADDRESS = 0x13; // eap id address in EAP-IDENTITY frame

int capture_eap_frames();
static void determine_eap_frame_type_then_response_eap_frame(u_char *args, const struct pcap_pkthdr* header, const uint8_t *frame);
int send_eap_frame(SEND_FRAME_TYPE type, const uint8_t *frame);

static void type_req_idnty_action(const uint8_t *frame);
static void type_req_md5_chg_action(const uint8_t *frame);
static void type_failure_action(const uint8_t *frame);
static void type_success_action(const uint8_t *frame);
static void type_error_action();

#endif
