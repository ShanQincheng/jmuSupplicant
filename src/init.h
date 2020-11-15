#ifndef INIT_
#define INIT_

#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <net/ethernet.h>
#include <errno.h>
#include <sys/ioctl.h>

#ifndef __linux
#include <net/if.h>
#include <netinet/in.h>
#include <net/if_dl.h>
#include <net/ethernet.h>
#else /* if BSD */
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_link.h>
#endif

#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <stdlib.h>
#include <unistd.h>


#include <pcap.h>

#define DEFAULT_DHCPMODE 0
#define MAX_PATH 255  // dhcp script max size 
#define SERVICE_SIZE 127  // service_name max size
#define ACCOUNT_SIZE 65  // username and password max size
//#define DEFAULT_NIC_NAME "bnep0"
#define MAC_LENGTH 6
#define NIC_MAXHOST 1025
#define NIC_SIZE  16 // the name of network interface card  max size

#define DEBUG 1

typedef struct nic_struct {
  char nic_name[NIC_SIZE]; // network interface card name
  uint8_t nic_MAC[ETHER_ADDR_LEN]; // network interface card MAC address
  struct in_addr ipaddr; // ip address
  struct in_addr netmask; // network mask
  struct in_addr gateway;
  struct in_addr dns;
} NIC_STRUCT;

const static uint8_t SERVICE_EDUCATION[] = {0xbd, 0xcc, 0xd3, 0xfd, 0xcd, 0xf8, 0xbd, 0xd3, 0xc8, 0xeb}; //教育网接入
const static uint8_t SERVICE_CHINA_UNICOM[] = {0xc1, 0xaa, 0xcd, 0xa8, 0xbf, 0xed, 0xb4, 0xf8, 0xbd, 0xd3, 0xc8, 0xeb}; // 联通宽带接入
const static uint8_t SERVICE_CHINA_MOBILE[] = {0xd2, 0xc6, 0xb6, 0xaf, 0xbf, 0xed, 0xb4, 0xf8, 0xbd, 0xd3, 0xc8, 0xeb}; // 移动宽带接入
const static uint8_t SERVICE_CHINA_TELECOM[] = {0xb5, 0xe7, 0xd0, 0xc5, 0xbf, 0xed, 0xb4, 0xf8, 0xbd, 0xd3, 0xc8, 0xeb}; // 电信宽带接入

const static unsigned int SERVICE_EDUCATION_LENGTH = 10; // bytes number
const static unsigned int SERVICE_CHINA_UNICOM_LENGTH = 12;
const static unsigned int SERVICE_CHINA_MOBILE_LENGTH = 12;
const static unsigned int SERVICE_CHINA_TELECOM_LENGTH = 12;

const static unsigned int DEFAULT_SERVICE_NAME_SIZE = 32;
const static char *DEFAULT_DHCPSCRIPT = "dhclient";
const static unsigned int DNS_LENGTH = 15;

void init_login_config();
void init_device();
static void init_gateway();
static void init_DNS();
static void init_netmask();
static void init_ipaddr();
static void init_service_name();
int init_NIC_name(NIC_STRUCT *nic_info);
int init_NIC_address(NIC_STRUCT *nic_info);
static void PrintInitConfig();

#endif








