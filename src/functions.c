// 
//=========================================================================
//
//  Filename: functions.c
//  
//  Description:
//
//    Version:  1.0
//    Created:  04/29/2018 09:14:30 P.M.
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

#include "functions.h"
#include "strnormalize.h"
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>


static char* get_md5_digest(const char *str, size_t length)
{
  static md5_byte_t digest[16];

  md5_state_t state;
  md5_init(&state);
  md5_init(&state);
  md5_append(&state, (const md5_byte_t *)str, length);
  md5_finish(&state, digest);

  return (char*)digest;
}

uint8_t
*calculate_the_eap_md5_value_in_response_md5_challenge_frame(
  const uint8_t id, const uint8_t *eap_request_md5_chag_value, unsigned int eap_md5_value_size)
{
  extern char *password;
  extern unsigned int password_length;
  uint8_t *uint8_type_calculation_result;
  char *md5_algo_input_array, *calculation_result;
  unsigned int i = 0;
  unsigned int md5_algo_input_array_length = sizeof(id) + password_length + eap_md5_value_size;

  md5_algo_input_array = (char *)malloc(md5_algo_input_array_length * sizeof(char));
  calculation_result = (char*)malloc(eap_md5_value_size * sizeof(char));
  uint8_type_calculation_result = (uint8_t *)malloc(
                                    eap_md5_value_size * sizeof(uint8_t));
  memset(md5_algo_input_array, 0, md5_algo_input_array_length);
  memset(calculation_result, 0, eap_md5_value_size);
  memset(uint8_type_calculation_result, 0, eap_md5_value_size);

  memcpy(md5_algo_input_array, &id, sizeof(id)); // cp id to input array
  memcpy((md5_algo_input_array + sizeof(id)), password, password_length); // cp password to input array
  memcpy(md5_algo_input_array + sizeof(id) + password_length,
         eap_request_md5_chag_value, eap_md5_value_size); // cp eap_request_md5_chag_value to input array

  // use the funciton get_md5_digest to calculate the EAP-MD5 Value in eap_response_md5_chag frame
  memcpy(calculation_result, get_md5_digest(md5_algo_input_array,
         md5_algo_input_array_length), eap_md5_value_size);

  // transfer the char* type result to uint8_t* type
  memcpy(uint8_type_calculation_result, calculation_result, eap_md5_value_size);

#if defined(DEBUG)
  fprintf(stdout, "md5 result == ");
  for(i = 0; i < eap_md5_value_size; i++) {
    fprintf(stdout, "%02X ", uint8_type_calculation_result[i]);

  }
#endif

  free(md5_algo_input_array);
  free(calculation_result);

  return uint8_type_calculation_result;
}



//------function----------------------------------------------------------
// name: 
//    code_convert
// description:
//    字符串编码转换
//------------------------------------------------------------------------
int code_convert(char *from_charset, char *to_charset,
             char *inbuf, size_t inlen, char *outbuf, size_t outlen)
{
  iconv_t cd;
  // 此处错误处理很重要, 否则交叉编译到路由器运行出现Bus error
  if((cd = iconv_open(to_charset,from_charset)) == (iconv_t)-1)
    return -1;

  if (cd==0)
    return -1;
  memset(outbuf,0,outlen);

  if (iconv (cd, &inbuf, &inlen, &outbuf, &outlen) == (size_t)-1)
    return -1;
  iconv_close(cd);
  return 0;
}

//added to convert GBK to utf-8
static char *gbk2utf(char *gbksrc, size_t gbklen)	/* GBK转UTF－8 */
{
    /* GBK一汉字俩字节，UTF-8一汉字3字节，二者ASCII字符均一字节
         所以这样申请是足够的了，要记得释放 */
    str_normalize_init();

    size_t utf8len = gbklen * 3 + 1;
    char *utf8dst = (char *)malloc(utf8len);

    memset(utf8dst,0,utf8len);

    char *temp=(char *)malloc(gbklen+5);
    memset(temp, 0, gbklen+5);
    memcpy(temp,gbksrc,gbklen);
    gbksrc = temp;
    gbklen = strlen(gbksrc);

    gbk_to_utf8(gbksrc, gbklen, &utf8dst, &utf8len);

    free(temp);

    return utf8dst;
}

void print_server_info(const uint8_t *frame)
{
  char            *msg_buf;
  char            *msg;
  uint16_t        msg_length;
  uint16_t        empty_length;
  uint16_t        account_info_offset;

  msg_length = ntohs(*(uint16_t*)(frame + 0x1a));
  empty_length = ntohs(*(uint16_t*)(frame + 0x1c + msg_length + 0x04));
  account_info_offset = 0x1c + msg_length + 0x06 + empty_length + 0x12 + 0x09;

  // success和failure报文系统信息的固定位置
  if (msg_length) {
    msg = (char*)(frame + 0x1c);
    /*code_convert ("gb2312", "utf-8",
                  msg, msg_length,
                  msg_buf, 1024);*/
    msg_buf=gbk2utf(msg,msg_length);
    if(strlen(msg_buf) > 0) {
        fprintf (stdout, ">>Ruijie 通知: %s\n", msg_buf);
        free(msg_buf);  //打印完就要释放
    }

  }

  // success报文关于用户账户信息 
  msg_length = *(uint8_t*)(frame + account_info_offset + 0x07);
  if (msg_length) {
    msg = (char*)(frame + account_info_offset + 0x08);
    /*code_convert ("gb2312", "utf-8",
                  msg, msg_length,
                  msg_buf, 1024);*/
    msg_buf=gbk2utf(msg,msg_length);
    if(strlen(msg_buf) > 0) {
        fprintf (stdout, ">>账户信息: %s\n", msg_buf);
        free(msg_buf);
    }

  }

  return;
}

//------function----------------------------------------------------------
// name: 
//    midnight_relogin
// description:
//    midnight 模式, 重新认证以保证稳定不掉线。
//    将 jmuSupplicant 各项 variables 恢复到初始状态, 以免存在
//    脏数据影响认证
//------------------------------------------------------------------------
int midnight_relogin()
{
  extern unsigned int midnight;
  extern char *user_input_ipaddr;
  extern char *user_input_mask;
  extern char *service_company;
  extern NIC_STRUCT nic_info;
  extern unsigned int midnight_mode_change_tail_data;
  extern unsigned int midnight;
  extern SEND_FRAME_TYPE current_state;

  // midnight模式只需重认证一次, 此时正在准备重新认证,
  // 这次成功后就不许要再次重认证了
  midnight = 0;  
  // 重认证时, start frame 和 response-md5-challenge frame 末端数据与
  // 普通认证时发送的不同。此处告知 construct_eap_frames.c 构造认证数
  // 据包时需要做对应的变动
  midnight_mode_change_tail_data = 1;
  user_input_ipaddr = NULL; // clean user_input_ipaddr, to get the network card real ip addr
  user_input_mask = NULL;
  service_company = NULL;
  // 重认证时服务名不能用'教育网接入',必须选择 '联通','电信'或'移动'
  // 这里写死,选联通
  service_company = (char*)calloc(1, sizeof(2));
  strcpy(service_company, "1");
  
  // 重新初始化认证参数
  init_login_config();
  alarm(0);

  if(init_NIC_address(&nic_info) == -1) { // get network interface card MAC, ip, mask
    int errnum = errno;
    fprintf(stderr, "Value of errno: %d\n", errnum);
    perror("Error printed by perror");
    fprintf(stderr, "Error get  nic address: %s\n", strerror( errnum ));

    exit(1);
  }
  
  // 认证失败后服务器会立刻向 supplicant 发送几次 request-identity frame
  // 等待并忽略掉这些 frame, 然后重新'干净'地认证
  sleep(5);

  alarm(10);
  
  current_state = EAPOL_START;
  
  // 发送 EAPOL-START frame, 重启认证
  send_eap_frame(EAPOL_START, NULL);

  return 0;
}


//------function----------------------------------------------------------
// name: 
//    relogin_when_receive_failure_frame
// description:
//    认证时失败, 自动重启认证 
//    将 jmuSupplicant 各项 variables 恢复到初始状态, 以免存在
//    脏数据影响认证
//------------------------------------------------------------------------
int relogin_when_receive_failure_frame()
{
  extern char *user_input_ipaddr;
  extern char *user_input_mask;
  extern char *user_input_ipaddr_bp;
  extern char *user_input_mask_bp;
  extern char *service_company;
  extern char *service_company_bp;
  extern unsigned int midnight;
  extern unsigned int midnight_bp;
  extern NIC_STRUCT nic_info;
  extern SEND_FRAME_TYPE current_state;

  static unsigned int relogin_number = 0; // 重认证次数,超过5次停止重认证


 if(relogin_number > 5)
 {
   fprintf(stdout, "\n\nregloin over 5 times, please check your username, password or service name\n\n");
   exit(1);
 }
 fprintf(stdout, "\n\nThe program is running relogin function.\n\n\n");
 if(user_input_ipaddr_bp != NULL)
  {
    // 用户输入的 ipaddr, 保存在 char **argv 数组中。无法 free()
    // 第二次至第五次重认证时, ipaddr 保存在 jmuSupplicant malloc()
    // 出来的内存中,因此可以正常 free()
    if(relogin_number)
      free(user_input_ipaddr);
    user_input_ipaddr = user_input_ipaddr_bp;
    user_input_ipaddr_bp = NULL;
  }
  if(user_input_mask_bp != NULL)
  {
    if(relogin_number)
      free(user_input_mask);
    user_input_mask = user_input_mask_bp;
    user_input_mask_bp = NULL;
  }
  if(midnight_bp)
  {
    midnight = midnight_bp;
    midnight_bp = 0;
  }
  if(service_company_bp != NULL)
  {
    if(relogin_number)
      free(service_company);
    service_company = service_company_bp;
    service_company = NULL;
  }
  relogin_number++;

  init_login_config();
  alarm(0);

  if(init_NIC_address(&nic_info) == -1) { // get network interface card MAC, ip, mask
    int errnum = errno;
    fprintf(stderr, "Value of errno: %d\n", errnum);
    perror("Error printed by perror");
    fprintf(stderr, "Error get  nic address: %s\n", strerror( errnum ));
  }

  sleep(10);

  alarm(10);
  current_state = EAPOL_START;

  send_eap_frame(EAPOL_START, NULL);
}



//------function----------------------------------------------------------
// name: 
//    HandleSigalrm
// description:
//    signal handler 函数, 通过 signal(alarm) 函数，查询 jmuSupplicant 
//    此时的运行状态。根据当前运行状态, 做出对应的动作。
//
//    ONLINE: 认证并登录成功，发送心跳包保持在线。
//    EAP_FAILURE: 认证并登录成功后,收到服务器发送的下线信息。退出程序
//    EAPOL_START: 已发送认证 frame,但未收到服务器的响应。
//------------------------------------------------------------------------
void HandleSigalrm(int sig, siginfo_t *siginfo, void *context)
{
  extern SEND_FRAME_TYPE current_state;
  extern pcap_t *descr;

  switch(current_state) {
  case ONLINE:
    // send_ethernet_frame(KEEP_ONLINE, eapol_heartbeat);
    KeepOnline();

    // Logs here
    openlog(NULL, LOG_PID|LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "Send an eapol heartbeat frame...");
    closelog();

    alarm(30);
    break;

  case EAP_FAILURE:
    pcap_breakloop(descr); // force pcap_loop() function return rather than looping
    break;

  case EAPOL_START:
    fprintf(stderr, "已发送认证信息，但未收到服务器响应包，请检查网络连接是否正常\n");
    pcap_breakloop(descr); // force pcap_loop() function return rather than looping
    break;

  default:
    break;
  }

  return;
}

//------function----------------------------------------------------------
// name: 
//    KeepOnline
// description:
//    发送心跳包保持在线
//------------------------------------------------------------------------
void KeepOnline()
{
  extern SEND_FRAME_TYPE current_state;
 
  if(current_state == ONLINE)
  {
    // Logs here
    openlog(NULL, LOG_PID|LOG_CONS, LOG_USER);
    syslog(LOG_INFO, "Send an eapol heartbeat frame...");
    closelog();

    send_eap_frame(ONLINE, NULL);
  }else exit(1);

  return;
}


//------function----------------------------------------------------------
// name: 
//    DaemonInit
// description:
//    daemon 模式初始化, 用于后台运行.功能正常
//    已经弃用,转为使用Linux库函数daemon()
//------------------------------------------------------------------------

/*
void DaemonInit()
{
  pid_t pid, sid;

  // Fork off the parent process
  pid = fork();
  // Error occur
  if (pid == -1) {
    exit(EXIT_FAILURE);
  }
  // If we get a good child pid, then
  // we can exit the parent process
  if (pid > 0) {
    exit(EXIT_SUCCESS);
  }

  // Change the file mode mask
  umask(0);

  // Create a new SID for the child process
  sid = setsid();
  // Error occur
  if (sid == -1) {
    // Log the failure
    exit(EXIT_FAILURE);
  }

  // change the current working directory
  if ((chdir("/")) < 0) {
    exit(EXIT_FAILURE);
  }

  // Close out the standard file descriptors
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);

  // Daemon-specific initialization goes here

  return;
}
*/


//------function----------------------------------------------------------
// name: 
//    LockRegister
// description:
//    初始化锁文件参数
//------------------------------------------------------------------------
int LockRegister(int fd, int cmd, int type, off_t offset, int whence, off_t len)
{
  struct flock lock;

  lock.l_type = type;  // F_RDLCK, F_WRLCK, F_UNLCK
  lock.l_start = offset;  // byte offset, relative to l_whence
  lock.l_whence = whence;  // SEEK_SET, SEEK_CUR, SEEK_END
  lock.l_len = len;  // #bytes (0 means to EOF)

  return(fcntl(fd, cmd, &lock)); // manipulate file descriptor
}


//------function----------------------------------------------------------
// name: 
//    LockTest
// description:
//    检测当前是否有 jmuSupplicant 实例正在运行
//------------------------------------------------------------------------
pid_t LockTest(int fd, int type, off_t offset, int whence, off_t len)
{
  struct flock lock;

  lock.l_type = type;  // F_RDLCK or F_WRLCK
  lock.l_start = offset;  // byte offset, relative to l_whence
  lock.l_whence = whence;  // SEEK_SET, SEEK_CUR, SEEK_END
  lock.l_len = len;  // #bytes (0 means to EOF)

  if (fcntl(fd, F_GETLK, &lock) < 0) {
    fprintf(stderr, "fcntl error\n");
    exit(EXIT_FAILURE);
  }

  if (lock.l_type == F_UNLCK)
    return 0;  // false, region isn't locked by another proc
  return lock.l_pid;  // true, return pid of lock owner
}


//------function----------------------------------------------------------
// name: 
//    KillJMUSupplicant
// description:
//    杀死 jmuSupplicant 后台运行的进程
//------------------------------------------------------------------------
int KillJMUSupplicant(int exit_flag, int fd, int type, off_t offset, int whence, off_t len)
{
  pid_t pid;
  if(exit_flag) {
    pid = LockTest(fd, type, offset, whence, len);
    if(pid > 0) {
      kill(pid, SIGKILL);
      CleanMemory();
    }
  }

  return 0;
}

//------function----------------------------------------------------------
// name: 
//    initiative_exit_program_with_already_running_check
// description:
//    用户请求杀死 jmuSupplicant 后台运行的进程
//    根据锁文件判断 jmuSupplicant 的运行状态并输出到控制台
//------------------------------------------------------------------------
int initiative_exit_program_with_already_running_check(int exit_flag, int fd, pid_t pid)
{
  if(exit_flag) {
    if(pid > 0) {
      KillJMUSupplicant(exit_flag, fd, F_WRLCK, 0, SEEK_SET, 0);
      fprintf(stdout, "Success kill the process\n");

      exit(EXIT_SUCCESS);
    } else {
      fprintf(stdout, "The process is not running\n");

      exit(EXIT_SUCCESS);
    }
  } else {
    if(pid > 0) {
      fprintf(stdout, "The process is running on background\n");

      exit(EXIT_SUCCESS);
    }
  }

  return 0;
}

//------function----------------------------------------------------------
// name: 
//    CleanMemory
// description:
//    释放内存
//------------------------------------------------------------------------
static int CleanMemory()
{
  extern char *username;
  extern char *password;
  extern char *user_input_gateway; // 由用户设定的四个报文参数
  extern char *user_input_dns;   // numbers-and-dots dns notation by user input
  extern char *user_input_ipaddr;   // numbers-and-dots ip notation by user input
  extern char *user_input_mask;   // number-and-dots mask notation by user input
  extern char *service_company; // login service name

/*
  if(username != NULL)
    free(username);
  if(password != NULL)
    free(password);
  if(user_input_gateway != NULL)
    free(user_input_gateway);
  if(user_input_dns != NULL)
    free(user_input_dns);
  if(user_input_ipaddr != NULL)
    free(user_input_ipaddr);
  if(user_input_mask != NULL)
    free(user_input_mask);
  if(service_company != NULL)
    free(service_company);
*/
  return 0;
}

