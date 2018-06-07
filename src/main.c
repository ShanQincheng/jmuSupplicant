// 
//=========================================================================
//
//  Filename: main.c
//  
//  Description:
//
//    Version:  1.0
//    Created:  04/28/2018 05:10:20 A.M.
//    Revision:  none
//    Compiler:  gcc
//
//    Author: codingstory, codingstory.tw@gmail.com
//
//    可从此文件了解 jmuSupplicant 的大致执行流程
//    1、初始化用户输入参数
//    2、检测是否后台已经有 jmuSupplicant 的实例正在运行
//    3、初始化认证登录信息,用户名,密码,服务名等
//    4、初始化网络设备,选择设备名,提取设备ip地址,netmask地址,MAC地址等信息
//    5、配置 signal handler,为定时发送心跳包保持在线做准备
//    6、初始化完毕,开始认证。发送 EAPOL START frame 给服务器请求认证登录,
//       此为认证过程中第一个步骤
//    7、捕获服务器返回的 Request EAP frames,用以执行后续认证操作。
//
//=========================================================================
//

#include <stdio.h>
#include <getopt.h>

#include "functions.h"
#include "init.h"
#include "eap_frames_operations.h"

const static char LOCK_FILE_PATH[23] = "/var/run/test_lock.pid";

int fd = -1; // lock file descriptor

static void ShowUsage()
{
  printf( "\n"
          "jmuSupplicant for JMU  \n"
          "\t  -- Client for Ruijie Authentication in JMU campus.\n"
          "\n"
          "  Usage:\n"
          "\t请使用 root 权限下运行。通常需要在命令行前加入 'sudo'。\n\n"
          "\t-u, --username        用户名,通常为学号。\n"
          "\t-p, --password        密码。\n"
          "\t-s, --service_company	服务名。\n"
          "\t          0(教育网),1(联通宽带接入),2(移动宽带接入),3(电信宽带接入)	\n\n" 
          "\n"
          "  可选参数:\n\n"
   //      "\t-g, --gateway         指定 Gateway(网关) 地址。 \n\n"

   //       "\t-d, --dns             指定 DNS 服务器地址。 \n\n"

          "\t--ip                  指定 ip 地址,推荐配合 mignight 模式中使用。 \n"
          "\t--mask                指定 Netmask(子网遮罩) 地址。 \n"
          "\t-i                    指定 网卡名称，则程序中不再要求用户手动选择网卡\n" 
          "\t-n                    开启 midnight 模式,断网后使用。\n\n"

          "\t-b, --background      认证成功后,jmuSupplicant进入 dameon 模式,后台运行。\n\n"

          "\t-k                    停止正在运行的 jmuSupplicant。\n\n"

          "\t-h, --help            展开 jmuSupplicant 运行帮助。\n\n"
          "\n"
          "  关于 jmuSupplicant:\n\n"
          "\tjmuSupplicant is a program developed individually and release under APGLv3 \n"
          "\tlicense as free software, with NO any relaiontship with Ruijie company.\n\n\n"

   //       "\tAnother codingstory work. Blog: https://codingstory.com.cn\n"
          "\t\t\t\t\t\t\t\t2018.06.01\n");
}


//
//------function----------------------------------------------------------
// name: 
//    InitArguments
// description:
//    获取 jmuSupplicant 运行时用户输入的参数 
//------------------------------------------------------------------------
//
static void InitArguments(int *argc, char ***argv)
{
  extern unsigned int background_running;           // background running
  extern unsigned int multiple_running;  // multiple running
  extern unsigned int midnight;  // login after school network cut off
  extern unsigned int exit_flag;
  char *dev; // 连接的设备名
  extern char *username;
  extern char *password;
  extern char *user_input_gateway; // 由用户设定的四个报文参数
  extern char *user_input_dns;   // numbers-and-dots dns notation by user input
  extern char *user_input_ipaddr;   // numbers-and-dots ip notation by user input
  extern char *user_input_mask;   // number-and-dots mask notation by user input
  extern char *service_company; // login service name
  extern char *network_interface_card_name; 
  
  // Option struct for progrm run arguments
  static struct option long_options[] = {
    {"help",        no_argument,        0,              'h'},
    {"background",  no_argument,        &background_running,    1},
    {"username",    required_argument,  0,              'u'},
    {"password",    required_argument,  0,              'p'},
    {"ip",          required_argument,  0,              4},
    {"mask",        required_argument,  0,              5},
    {"gateway",     required_argument,  0,              'g'},
    {"dns",         required_argument,  0,              'd'},
    {"service_company", required_argument, 0,  's'},
    {"interface_card",  required_argument, 0, 'i'}, 
    {0, 0, 0, 0}
  };
  int c;
  while (1) {

    /* getopt_long stores the option index here. */
    int option_index = 0;
    c = getopt_long ((*argc), (*argv), "u:s:p:g:d:hbkmni",
                     long_options, &option_index);
    if (c == -1)
      break;
    switch (c) {
    case 0:
      break;
    case 'b':
      background_running = 1;
      break;
    case 4:
      user_input_ipaddr = optarg;
      break;
    case 5:
      user_input_mask = optarg;
      break;
    case 'n':
      midnight = 1;
      break;
    case 'u':
      username = optarg;
      break;
    case 'p':
      password = optarg;
      break;
    case 'g':
      user_input_gateway = optarg;
      break;
    case 'd':
      user_input_dns = optarg;
      break;
    case 's':
      service_company = optarg;
      break;
    case 'k':
      exit_flag = 1;
      break;
    case 'm':
      multiple_running = 1;
      break;
    case 'i':
      network_interface_card_name = optarg; // 网络设备信息结构体,包含 ip, netmask, gateway 等等
      break;
    case 'h':
      ShowUsage();
      exit(EXIT_SUCCESS);
      break;
    case '?':
      if (optopt == 'u' || optopt == 'p'||
          optopt == 'g'|| optopt == 'd')
        fprintf (stderr, "选项 -%c 需要加入参数.\n", optopt);
      exit(EXIT_FAILURE);
      break;
    default:
      fprintf (stderr,"未知的选项 `\\x%x'.\n", c);
      exit(EXIT_FAILURE);
    }
  }

  return;
}


int main(int argc, char **argv)
{
  pid_t pid;  // running process pid
  extern unsigned int exit_flag; // 程序退出参数
  extern unsigned int multiple_running; // 允许程序多个process同时运行
  struct sigaction sa; // examine and change a signal action

  // O_CREAT, if the specified file does not exist, it will be created by open()
  // O_RDWR, access modes, read and write
  fd = open(LOCK_FILE_PATH, O_CREAT | O_RDWR);
  if (fd == -1) {
    fprintf(stderr, "Can't open or create the lock file\n");
    exit(EXIT_FAILURE);
  }

  // 初始化用户输入参数
  InitArguments(&argc, &argv);
  
  // 检测是否后台已经有此程序的实例正在运行
  if(!multiple_running) {
    pid = LockTest(fd, F_WRLCK, 0, SEEK_SET, 0);
    initiative_exit_program_with_already_running_check(exit_flag, fd, pid);
  }

  // 初始化认证登录信息,用户名,密码,服务名等
  init_login_config();
  // 初始化网络设备,选择网卡,提取网卡ip地址,netmask地址,MAC地址等信息
  init_device();

  // 配置 signal handler,为定时发送心跳包保持在线做准备
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = &HandleSigalrm;
  sigfillset(&sa.sa_mask);
  if(sigaction(SIGALRM, &sa, NULL) == -1) {
    fprintf(stderr, "Error: cannot handle SIGALRM.");
  }
  
  alarm(10);
  // 初始化完毕,开始认证。发送 EAP-START frame 给服务器请求认证登录,
  // 此为认证过程中第一个步骤
  send_eap_frame(EAPOL_START, NULL);
  
  // 捕获服务器返回的 EAP frames,用以执行后续认证操作。
  capture_eap_frames();
  
  // 保持在线
  while(1)
  {
    sleep(20);
    KeepOnline();
  }
  return 0;
}

