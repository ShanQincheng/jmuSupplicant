#ifndef CONSTRUCT_FRAMES_
#define CONSTRUCT_FRAMES_

#define DEBUG 1
//If using macos we should use sys/malloc.h instead of malloc.h
//
//	Evsio0n <admin@openjmu.xyz> 2020/7/28/7:14:08
//
//We should add different include type for libpcap to port it on macOS

#ifndef __linux
#include <sys/malloc.h>
#else /* BSD like System macOS*/
#include <malloc.h>
#endif
#include <string.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>

#include "init.h"
#include "functions.h"
#include "mentohust_encryption/md5.h"
#include "mentohust_encryption/mentohustV4.h"
#include "mentohust_encryption/mento_myfun.h"

// EAPOL START FRAME
const static unsigned int ETHERNET_TYPE_LENGTH = 2;
const static unsigned int ETHERNET_HEADER_LENGTH = 14;
const static unsigned int EAPOL_VERSION_LENGTH = 1;
const static unsigned int EAPOL_TYPE_LENGTH = 1;
const static unsigned int EAPOL_FRAME_LENGTH = 2;
const static unsigned int ETHERNET_PADDING_LENGTH = 42;
const static unsigned int ETHERNET_TRAILER_LENGTH = 507;

const static unsigned int EAPOL_START_IP_ADDR = 0X17;
const static unsigned int EAPOL_START_NETMASK_ADDR = 0X1B;
const static unsigned int EAPOL_START_GATEWAY_ADDR = 0X1F;
const static unsigned int EAPOL_START_SERVICE_NAME_ADDR = 0x193;

// EAP RESPONSE IDENTITY FRAME
const static unsigned int EAP_HEADER_LENGTH = 4;
const static unsigned int EAP_TYPE_LENGTH = 1;
const static unsigned int EAP_IDENTITY_PADDING_LENGTH = 25;
const static unsigned int EAP_IDENTITY_TRAILER_LENGTH = 524;
const static unsigned int EAP_IDENTITY_RESPONSE_SERVICE_NAME_ADDR = 0x1a4;
const static unsigned int EAP_IDENTITY_RESPONSE_IP_ADDR = 0x28;
const static unsigned int EAP_IDENTITY_RESPONSE_NETMASK_ADDR = 0X2c;
const static unsigned int EAP_IDENTITY_RESPONSE_GATEWAY_ADDR = 0X30;

const static unsigned int EAP_ID_ADDRESS_IN_EAP_IDENTITY_REQUEST_FRAME = 0X13;

// EAP RESPONSE MD5 CHALLENGE FRAME
const static unsigned int EAP_MD5_VALUE_SIZE_LENGTH = 1;
const static unsigned int EAP_MD5_VALUE_LENGTH = 16;
const static unsigned int EAP_MD5_CHALLENGE_PADDING_LENGTH = 8;
const static unsigned int EAP_MD5_CHALLENGE_TRAILER_LENGTH = 545;
const static unsigned int SERVICE_NAME_LENGTH = 32;

const static unsigned int EAP_MD5_RESPONSE_IP_ADDR = 0X39;
const static unsigned int EAP_MD5_RESPONSE_NETMASK_ADDR = 0X3D;
const static unsigned int EAP_MD5_RESPONSE_GATEWAY_ADDR = 0X41;
const static unsigned int EAP_MD5_RESPONSE_COMPUTE_PASSWORD_ADDR = 0XB8;
const static unsigned int EAP_MD5_RESPONSE_COMPUTE_V4_ADDR = 0X121;
const static unsigned int EAP_MD5_RESPONSE_SERVICE_NAME_ADDR = 0X1B5;

const static unsigned int EAP_ID_ADDRESS_IN_EAP_MD5_REQUEST_FRAME = 0X13;
const static unsigned int EAP_MD5_VALUE_SIZE_ADDRESS_IN_EAP_MD5_REQUEST_FRAME = 0X17;

// EAPOL HEARTBEAT FRAME
const static unsigned int EAPOL_HEARTBEAT_DATA_LENGTH = 27;

// use in midnight mode
const static unsigned SWITCH_SERVICE_TAIL_DATA_START_LENGTH = 56;
const static unsigned SWITCH_SERVICE_TAIL_DATA_MD5_CHALLENGE_LENGTH = 66;
const static unsigned TAIL_DATA_ADDRESS_IN_START = 0x208;
//const static unsigned TAIL_DATA_ADDRESS_IN_IDENTITY = 0x210;
const static unsigned TAIL_DATA_ADDRESS_IN_MD5_CHALLENGE = 0x221;

static void construct_ethernet_frame_header(uint8_t *packet, const uint8_t *src_MAC, const uint8_t *dst_MAC, const uint16_t ether_type);
void construct_eapol_start_frame(const uint8_t *frame);
void construct_eap_response_identity_frame(const uint8_t *frame);
void construct_eap_response_md5_challenge_frame(const uint8_t *frame);
void construct_eapol_heartbeat_frame(const uint8_t *frame);

// 断网后重新认证, 分别填充到 START FRAME 和 MD5-CHALLENGE FRAME 的尾部数据
const static uint8_t SWITCH_SERVICE_TAIL_DATA_START[] = {0x13, 0x11, 0x64, 0x04, 0x00, 0x01, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x6b, 0x03, 0x00, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x70, 0x03, 0x40, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x6f, 0x03, 0x00, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x79, 0x03, 0x02, 0x1a, 0x0f, 0x00, 0x00, 0x13, 0x11, 0x76, 0x09, 0x38, 0x2e, 0x38, 0x2e, 0x34, 0x2e, 0x34};
const static uint8_t SWITCH_SERVICE_TAIL_DATA_MD5_CHALLENGE[] = {0x13, 0x11, 0x62, 0x03, 0x00, 0x1a, 0x0a, 0x00, 0x00, 0x13, 0x11, 0x64, 0x04, 0x00, 0x01, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x6b, 0x03, 0x00, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x70, 0x03, 0x40, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x6f, 0x03, 0x00, 0x1a, 0x09, 0x00, 0x00, 0x13, 0x11, 0x79, 0x03, 0x02, 0x1a, 0x0f, 0x00, 0x00, 0x13, 0x11, 0x76, 0x09, 0x38, 0x2e, 0x38, 0x2e, 0x34, 0x2e, 0x34};


#endif


