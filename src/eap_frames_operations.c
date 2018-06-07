// 
//=========================================================================
//
//  Filename: eap_frames_operation.c
//  
//  Description:
//
//    Version:  1.0
//    Created:  04/29/2018 08:58:12 P.M.
//    Revision:  none
//    Compiler:  gcc
//
//    Author: codingstory, codingstory.tw@gmail.com
//    
//    1、从网络设备捕获 EAP frame
//    2、判断捕获的 Request EAP frame type。
//    3、发送与之对应的 EAP RESPONSE frame 给服务器进行后续的认证。   
//      
//  
//=========================================================================
//

#include "eap_frames_operations.h"

uint8_t eapol_start[1000];  // eapol start frame
uint8_t eap_response_identity[1000]; 
uint8_t eap_response_md5_challenge[1000];  
uint8_t eapol_heartbeat[45];
pcap_t *descr = NULL;// PCAP packet capture descriptor for the specified interface.
SEND_FRAME_TYPE current_state;
unsigned int midnight_mode_change_tail_data = 0;
extern NIC_STRUCT nic_info;

//
//------function----------------------------------------------------------
// name: 
//    capture_eap_frames
// description:
//    不断监听网络设备。从捕获到的数据包中,筛选出 EAP frame 
//------------------------------------------------------------------------
//
int capture_eap_frames()
{
  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  //pcap_t *descr;
  const uint8_t *frame;
  struct pcap_pkthdr hdr;  // pcap.h
  struct ether_header *eptr;  // net/ethernet.h
  struct bpf_program fp; // hold compiled program
  bpf_u_int32 netmask = nic_info.netmask.s_addr;  // the netmask of our sniffing device
  char filter_exp[256];  // pcap_compile() filter parameter
  // 作为参数传递给 pcap_compile() 函数，指定从捕获到的数据包中筛选 EAP Frame 
  const char filter_exp_format[] = "ether[12:2]=0x888e and ether dst %02X:%02X:%02X:%02X:%02X:%02X"; 

  // Open a PCAP packet capture descriptor for the specified interface.
  descr = pcap_open_live(nic_info.nic_name, SNAP_LENGTH, 0, -1,  pcap_errbuf);
  if(descr == NULL) {
    fprintf(stderr, "%s", pcap_errbuf);

    return -1;
  }

  // compile the program, filter frames which contains ethernet interface MAC address
  snprintf(filter_exp, sizeof(filter_exp),filter_exp_format,
           nic_info.nic_MAC[0], nic_info.nic_MAC[1], nic_info.nic_MAC[2],
           nic_info.nic_MAC[3], nic_info.nic_MAC[4], nic_info.nic_MAC[5]); // FILTER_STR ether[12:2] = 0x888e and ether dst "ether interface MAC"

#if defined(DEBUG)
  printf("filter_exp_format is : %s\n", filter_exp_format);
  printf("filter_exp is : %s\n", filter_exp);
#endif

  if(pcap_compile(descr, &fp, filter_exp, 0, netmask) == -1) {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(descr));

    return -1;
  }
  if(pcap_setfilter(descr, &fp) == -1) {
    fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(descr));

    return -1;
  }

  // stratring sniff eap frames
  // 根据捕获到的服务器发送的不同类型的 Request EAP Frame,回应对应的 EAP frame 用以认证
  pcap_loop(descr, -1, determine_eap_frame_type_then_response_eap_frame, NULL);

  // CLose the PCAP descriptor
  pcap_close(descr);

  return 0;
}

//
//------function----------------------------------------------------------
// name: 
//    determine_eap_frame_type_then_response_eap_frame
// description:
//    提取 Request EAP frame 中的 EAP TYPE 数据, 以确定此 EAP frame type
//          
//------------------------------------------------------------------------
//
static void determine_eap_frame_type_then_response_eap_frame(u_char *args, const struct pcap_pkthdr* header, const uint8_t *frame)
{

#if defined(DEBUG)
  printf("EAP TYPE KEY VALUE is: %02x %02x\n", frame[22], frame[18]);
#endif

  // type request identity
  if(frame[22] == 0x01 && frame[18] == 0x01) {
    type_req_idnty_action(frame);

    // type request md5 challenge
  } else if(frame[22] == 0x04 && frame[18] == 0x01) {
    type_req_md5_chg_action(frame);

    // type eap failure
  } else if(frame[18] == 0x04) {
    type_failure_action(frame);

    // type eap success
  } else if(frame[18] == 0x03) {
//    type_success_action(frame);
    type_success_action(frame);
  
  } else {
    type_error_action();
  }

  return;
}

static void type_req_idnty_action(const uint8_t *frame)
{
  current_state = EAP_REQUEST_IDENTITY;
  send_eap_frame(EAP_REQUEST_IDENTITY, frame);

  return;
}

static void type_req_md5_chg_action(const uint8_t *frame)
{
  current_state = EAP_REQUEST_MD5_CHALLENGE;
  send_eap_frame(EAP_REQUEST_MD5_CHALLENGE, frame);

  return;
}

static void type_failure_action(const uint8_t *frame)
{
  fprintf(stderr, "receive failure packet from server\n");
  current_state = EAP_FAILURE;
  print_server_info(frame);
//  print_notification_msg(frame);
// Logs here
  openlog(NULL, LOG_PID|LOG_CONS, LOG_USER);
  syslog(LOG_INFO, "Receive eap failure frame, program terminating...");
  closelog();

  if(relogin_when_receive_failure_frame() != 0)
  {
    fprintf(stdout, "Attemp to relogin after program received failure frame failed.\n");
    exit(1);
  }


  return;
}

static void type_success_action(const uint8_t *frame)
{
  extern unsigned int background_running;
  extern unsigned int midnight;
  extern int fd;  // lock file descriptor

  current_state = ONLINE;
  print_server_info(frame);
//  print_notification_msg(frame);
  send_eap_frame(EAP_SUCCESS, frame);

  // 如果仅是后台运行,不是midnight模式后台运行的话
  if(!midnight && background_running) {

    daemon(1, 0); // create child process force the program running on background
    if(LockRegister(fd, F_SETLKW, F_WRLCK, 0, SEEK_SET, 0) == -1) {
      fprintf(stderr, "Lock file failed\n");
      exit(EXIT_FAILURE);
    } else {
      fprintf(stdout, "Lock file success\n");
    }

//    pcap_breakloop(descr);  
  }

  // midnight 模式, 重新登录保持长时间不断线
  if(midnight == 1)
  {
    midnight_relogin();
  
  }else pcap_breakloop(descr); // exit pcap capture process 

  return;
}

static void type_error_action()
{
  current_state = ERROR;
  fprintf(stderr, "Error eap type\n");

  exit(1);
}



//------function----------------------------------------------------------
// name: 
//    send_eap_frame
// description:
//    发送与之对应的 RESPONSE EAP frame (EAPOL-START frame 不算) 给服务器
//    进行后续的认证
//------------------------------------------------------------------------
int send_eap_frame(SEND_FRAME_TYPE type, const uint8_t *frame)
{
  uint8_t *send_eap_frame_data;
//  const struct pcap_pkthdr* header;
  unsigned int send_eap_frame_data_length;
//  const struct ether_header *ethernet_header;
//  uint8_t *eap_md5_value_size = NULL;
//  uint8_t eap_request_md5_value[EAP_MD5_VALUE_LENGTH]; // 该hex数组从服务器发送的 request-md5-challenge frame 中提取
//  uint8_t eap_id = 0x01; // default 0x01, 详见 RFC 3748
  extern unsigned int midnight;

  switch(type) {
  case EAPOL_START:
//    ethernet_header = (struct ether_header*)(frame); // extract ethernet header values
    construct_eapol_start_frame(frame);
    send_eap_frame_data = eapol_start;
    send_eap_frame_data_length = 1000;

    fprintf(stdout, "sending eapol start frame\n");
    break;

  case EAP_REQUEST_IDENTITY:
 //   ethernet_header = (struct ether_header*)(frame);  // extract ethernet header values
    
//    eap_id = frame[EAP_ID_ADDRESS];
    construct_eap_response_identity_frame(frame);
    send_eap_frame_data = eap_response_identity;
    send_eap_frame_data_length = 1000;

    fprintf(stdout, "sending eap_response_identity frame\n");
    break;

  case EAP_REQUEST_MD5_CHALLENGE:
//    ethernet_header = (struct ether_header*)(frame); // extract ethernet header values
    
    // copy eap md5 value from request md5-challenge-frame sent by server
//    strncpy(eap_request_md5_value, frame+24, EAP_MD5_VALUE_LENGTH);
//    eap_md5_value_size = (uint8_t*)malloc(1 * sizeof(uint8_t));
//    memcpy(eap_md5_value_size, (frame + 0x17), 1);
//    construct_eap_response_md5_challenge_frame(ethernet_header->ether_shost, eap_request_md5_value, eap_md5_value_size, frame);
    construct_eap_response_md5_challenge_frame(frame);
    send_eap_frame_data = eap_response_md5_challenge;
    send_eap_frame_data_length = 1000;

    fprintf(stdout, "sending eap_md5_challenge frame\n");
    break;

  case EAP_SUCCESS:
    // midnight_relogin() fucion not use anymore
    //if(midnight)
    //  midnight_relogin();

//    ethernet_header = (struct ether_header*)(frame); // extract ethernet header values
//    construct_eapol_heartbeat_frame(ethernet_header->ether_shost, frame);
    construct_eapol_heartbeat_frame(frame);
    send_eap_frame_data = eapol_heartbeat;
    send_eap_frame_data_length = 45;

    fprintf(stdout, "login success !\n");
    break;

  case ONLINE:
    fillEchoPacket(eapol_heartbeat);
    send_eap_frame_data = eapol_heartbeat;
    send_eap_frame_data_length = 45;

    break;

  default:
    fprintf(stdout, "wrong send frame type.%02x\n", type);
    exit(EXIT_FAILURE);
  }

  // open a pcap packet capture descriptor for the specified interface.
  char pcap_errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* descr = pcap_open_live(nic_info.nic_name, SNAP_LENGTH, 1, 1000,  pcap_errbuf);
  if(descr == NULL) {
    fprintf(stderr, "%s", pcap_errbuf);
  }
  if(!descr) {
    fprintf(stdout, "can't live ethernet interface\n");

    return -1;
  }

  // write the ethernet frame to the interface.
  if(pcap_inject(descr, send_eap_frame_data, send_eap_frame_data_length) == -1)
  {
    fprintf(stderr, "error occur when seding %d frame: %s\n", type, pcap_geterr(descr));
    pcap_perror(descr, 0);
    pcap_close(descr);
//    free(eap_md5_value_size);

    return -1;
  }

  // clean sent frames
  switch(type) {
  case EAPOL_START:
    memset(eapol_start, 0, sizeof(eapol_start));
    break;

  case EAP_REQUEST_IDENTITY:
    memset(eap_response_identity, 0, sizeof(eap_response_identity));
    break;

  case EAP_REQUEST_MD5_CHALLENGE:
    memset(eap_response_md5_challenge, 0, sizeof(eap_response_md5_challenge));
//    free(eap_md5_value_size);
    break;

  case EAP_SUCCESS:
    break;

  case ONLINE:
    break;

  dafault:
    fprintf(stderr, "wrong frame type to be cleaned !\n");
    exit(EXIT_FAILURE);
  }
  send_eap_frame_data = NULL;

  // close the pcap descriptor
  pcap_close(descr);

  return 0;
}



