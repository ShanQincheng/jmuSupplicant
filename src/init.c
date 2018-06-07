// 
//==================================================================
//
//  Filename: init.c
//  
//  Description:
//
//    Version:  1.0
//    Created:  04/28/2018 06:12:18 A.M.
//    Revision:  none
//    Compiler:  gcc
//
//    Author: codingstory, codingstory.tw@gmail.com
//
//    1、根据用户的输入参数初始化认证信息(username,password,
//       midnight mode, background running, service name and so on)
//    2、初始化网络设备信息(device name, device ipaddr,netmask, MAC), 
//       网络设备用于发送和接收认证数据
//       
//==================================================================
//


#include "init.h"

unsigned int background_running = 0; // 默认不会后台运行
unsigned int multiple_running = 0; // 默认只允许一个 jmuSupplicant 实例运行
unsigned int midnight = 0; // 断网后登录
unsigned int exit_flag = 0; // 用户主动杀死后台运行的 jmuSupplicant 进程
char *username = NULL;
char *password = NULL;
char *user_input_gateway = NULL; // user input dns dotted pair address
char *user_input_dns = NULL;
char *user_input_ipaddr = NULL;
char *user_input_mask = NULL;
char *service_company = NULL;  // 服务名,0教育网,1联通,2移动,3电信
uint8_t *service_name = NULL; //  Hex 格式服务名, 用于填充到认证 frame 中
char *network_interface_card_name = NULL; // 用于存储用户输入的网卡名
unsigned int username_length = 0;
unsigned int password_length = 0;
unsigned int ipaddr_length = 0;
unsigned int mask_length = 0;
NIC_STRUCT nic_info;  // 网络设备信息结构体,包含 ip, netmask, gateway 等等

// 保存参数信息, 用于登录失败重新登陆
char *username_bp = NULL;
char *password_bp = NULL;
char *user_input_ipaddr_bp = NULL;
char *user_input_mask_bp = NULL;
char *service_company_bp = NULL;
unsigned int midnight_bp = 0;


//------function----------------------------------------------------------
// name: 
//    init_login_config
// description:
//    根据用户的输入参数初始化认证信息
//------------------------------------------------------------------------
void init_login_config()
{
  // 初始化 NIC_STRUCT structure
  nic_info.ipaddr.s_addr = -1;
  nic_info.netmask.s_addr = -1;
  nic_info.gateway.s_addr = -1;
  nic_info.dns.s_addr = -1;
  memset(nic_info.nic_MAC, '\0', sizeof(ETHER_ADDR_LEN * sizeof(uint8_t)));
  
  // 判断用户是否输入用户名和密码
  if(username == NULL || password == NULL) {
    fprintf(stderr, "似乎没有输入认证帐号或密码.\n"
            "尝试运行 'sudo ./jmuSupplicant --help' 获取使用方法。\n");
    exit(EXIT_FAILURE);
  }
  username_length = strlen(username);
  password_length = strlen(password);

  // 如果用户指定了断网登录模式,保存下来用以认证失败时重新认证
  if(midnight == 1)
  {
    midnight_bp = midnight;
  }

  if(network_interface_card_name != NULL)
  {
   memset(nic_info.nic_name, '\0', sizeof(NIC_SIZE * sizeof(char)));
   memcpy(nic_info.nic_name, network_interface_card_name, sizeof(nic_info.nic_name));
  }

#if defined(DEBUG)
  fprintf(stdout, "the received password from user input is : %s\n"
          "and the password length is %d\n", password, password_length);
#endif

  init_gateway();
  init_DNS();
  init_netmask();
  init_ipaddr();
  init_service_name();

  return;
}

//------function----------------------------------------------------------
// name: 
//    InitDevice
// description:
//    初始化网络设备,获取网络设备 name,ipaddr,netmask,MAC 
//    并填充到 NIC_STRUCT 中
//------------------------------------------------------------------------
void init_device()
{

  if(network_interface_card_name == NULL && nic_info.nic_name != NULL) { // specify a network interface card
    memset(nic_info.nic_name, '\0', sizeof(NIC_SIZE * sizeof(char)));
    if(strlen(nic_info.nic_name) == 0) {
      init_NIC_name(&nic_info);
      printf("network interface card name:  %s\n", nic_info.nic_name);
    }
  }else printf("network interface card name:  %s\n", nic_info.nic_name);

//  system(dhcp_script);
  memset(nic_info.nic_MAC, '\0', sizeof(ETHER_ADDR_LEN * sizeof(uint8_t)));
  if(init_NIC_address(&nic_info) == -1) { // get network interface card MAC, ip, mask
    int errnum = errno;
    fprintf(stderr, "Value of errno: %d\n", errnum);
    perror("Error printed by perror");
    fprintf(stderr, "Error get  nic address: %s\n", strerror( errnum ));

    exit(1);
  }

  PrintInitConfig();
  return;
}

//------function----------------------------------------------------------
// name: 
//    InitGateway
// description:
//    If user has inputted Gateway, converts it from the IPv4 
//    numbers-and-dots notation into binary form (in network byte 
//    order), and stores it in the structure that 
//    &nic_info.gateway points to.
//------------------------------------------------------------------------
static void init_gateway()
{
  if(user_input_gateway != NULL) {
    int s, domain;
    domain = AF_INET;

    if(inet_aton(user_input_gateway, &nic_info.gateway) == 0) {
      fprintf(stderr, "Invalid gateway address\n");
      exit(EXIT_FAILURE);
    }
  } 

  return;
}

static void init_DNS()
{
  // the same is true for dns
  if(user_input_dns != NULL) {
    int s, domain;
    domain = AF_INET;
   
    if(inet_aton(user_input_dns, &nic_info.dns) == 0) {
      fprintf(stderr, "Invalid DNS server address\n");
      exit(EXIT_FAILURE);
    }
  }   

  return;
}

static void init_netmask()
{
 // the same is true for netmask
  if(user_input_mask != NULL) {
    int s, domain;
    domain = AF_INET;
    if(inet_aton(user_input_mask, &nic_info.netmask) == 0) {
      fprintf(stderr, "Invalid netmask address\n");
      exit(EXIT_FAILURE);
    }
    // 如果用户指定了 netmask 地址,保存下来用以认证失败时重新认证
    mask_length = strlen(user_input_mask);
    user_input_mask_bp = (char*)calloc(mask_length + 1, sizeof(char));
    memcpy(user_input_mask_bp, user_input_mask, mask_length + 1);
  } 
  
  return;
}

static void init_ipaddr()
{
  // the same is true for ipaddr
  if(user_input_ipaddr != NULL) {
    int s, domain;
    domain = AF_INET;
    if(inet_aton(user_input_ipaddr, &nic_info.ipaddr) == 0) {
      fprintf(stderr, "Invalid ip address\n");
      exit(EXIT_FAILURE);
    }
    // 如果用户指定了 ip 地址,保存下来用以认证失败时重新认证
    ipaddr_length = strlen(user_input_ipaddr);
    user_input_ipaddr_bp = (char*)calloc(ipaddr_length + 1, sizeof(char));
    memcpy(user_input_ipaddr_bp, user_input_ipaddr, ipaddr_length + 1);
  } 

  return;
}

static void init_service_name()
{
  if(service_company == NULL) { // 用户未输入服务名,默认以'教育网'登录
    service_name = (uint8_t*)malloc(DEFAULT_SERVICE_NAME_SIZE * sizeof(uint8_t));
    memset(service_name, 0x00, DEFAULT_SERVICE_NAME_SIZE);
    memcpy(service_name, SERVICE_EDUCATION, SERVICE_EDUCATION_LENGTH);
  } else {
    // 用户指定了'服务名',保存下来用以认证失败时重新认证
    service_company_bp = (char*)calloc(2, sizeof(char));
    memcpy(service_company_bp, service_company, 2);

    // 判断'服务名'具体为哪一个
    unsigned int integer_type_service_company = atoi(service_company);
    integer_type_service_company %= 4;
    switch(integer_type_service_company) {
    // Education network
    case 0:
      service_name = (uint8_t*)malloc(DEFAULT_SERVICE_NAME_SIZE * sizeof(uint8_t));
      memset(service_name, 0x00, DEFAULT_SERVICE_NAME_SIZE);
      memcpy(service_name, SERVICE_EDUCATION, SERVICE_EDUCATION_LENGTH);
      break;
    // China Unicom network
    case 1:
      service_name = (uint8_t*)malloc(DEFAULT_SERVICE_NAME_SIZE * sizeof(uint8_t));
      memset(service_name, 0x00, DEFAULT_SERVICE_NAME_SIZE);
      memcpy(service_name, SERVICE_CHINA_UNICOM, SERVICE_CHINA_UNICOM_LENGTH);
      break;
    // China mobile network
    case 2:
      service_name = (uint8_t*)malloc(DEFAULT_SERVICE_NAME_SIZE * sizeof(uint8_t));
      memset(service_name, 0x00, DEFAULT_SERVICE_NAME_SIZE);
      memcpy(service_name, SERVICE_CHINA_MOBILE,SERVICE_CHINA_MOBILE_LENGTH);
      break;
    // China Telecom network
    case 3:
      service_name = (uint8_t*)malloc(DEFAULT_SERVICE_NAME_SIZE * sizeof(uint8_t));
      memset(service_name, 0x00, DEFAULT_SERVICE_NAME_SIZE);
      memcpy(service_name, SERVICE_CHINA_TELECOM, SERVICE_CHINA_TELECOM_LENGTH);
      break;
    }
  }

  return;
}


//------function----------------------------------------------------------
// name: 
//    init_NIC_name
// description:
//    获取并显示电脑上所有网络设备名称,用户选择后存储名称至 NIC_STRUCT
//------------------------------------------------------------------------
int init_NIC_name(NIC_STRUCT *nic_info)
{
  struct ifaddrs *ifaddr, *ifa;
  int family, s, n;
  char hbuf[NIC_MAXHOST];
  size_t available_adapter_num = 0, choosed_adapter = 0; // 可选的网络设备数量; 被选择的网络设备序号
  char **available_adapter_name = NULL, **more_available_adapter_names = NULL; // 可选的网络设备名; realooc()函数需要用到的指针

  if (getifaddrs(&ifaddr) == -1) {
    printf("%s", strerror(errno));
  }

  /* Walk through linked list, maintaining head pointer so we
   * can free list later
   */
  for(ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
    if (ifa->ifa_addr == NULL)
      continue;
    family = ifa->ifa_addr->sa_family;
    if(ifa->ifa_flags & IFF_LOOPBACK)
      continue;
    if( family == AF_INET ) { // only use ipv4
      s = getnameinfo(ifa->ifa_addr,
                      (family == AF_INET) ? sizeof(struct sockaddr_in) :
                      sizeof(struct sockaddr_in6),
                      hbuf, NIC_MAXHOST,
                      NULL, 0, NI_NUMERICHOST);
      if(s != 0) {
        continue;
      } else {
        if(strlen(ifa->ifa_name) >= IFNAMSIZ) // avoid adapter name exceed sizeof( ifr.ifr_name )
          continue;
        available_adapter_num++;
        /*
         * (re)allocating adapters name array for user to chose
         */
        if(available_adapter_name == NULL) {
          available_adapter_name = (char**)calloc(1, sizeof(char*));
          if(available_adapter_name == NULL) {
            printf("Error (re)allocating adapters name memory (char **)");
            exit(EXIT_FAILURE);
          }
          available_adapter_name[(int)available_adapter_num - 1] = (char*)calloc(IFNAMSIZ, sizeof(char));
          if(available_adapter_name[(int)available_adapter_num - 1] == NULL) {
            printf("Error (re)allocating adapters name memory (available_adapter_name[0])");
            exit(EXIT_FAILURE);
          }
        } else {
          more_available_adapter_names = (char**)realloc(available_adapter_name, available_adapter_num * sizeof(char*));
          if (more_available_adapter_names != NULL) {
            available_adapter_name = more_available_adapter_names;
            available_adapter_name[(int)available_adapter_num - 1] = (char*)calloc(IFNAMSIZ, sizeof(char));
            if(available_adapter_name[(int)available_adapter_num - 1] == NULL) {
              printf("Error (re)allocating adapters name memory (available_adapter_name[%zu])", available_adapter_num - 1);
              exit(EXIT_FAILURE);
            }

          } else {
            free (available_adapter_name);
            printf("Error reallocating adapters name memory");
            exit(EXIT_FAILURE);
          }
        }

        strcpy(available_adapter_name[available_adapter_num - 1], ifa->ifa_name); // strcpy() the device name
        printf("[ %zu ] %s  <%s>\n", available_adapter_num,  ifa->ifa_name, hbuf); // 打印到控制台供用户选择输入
      }
    } else {
      continue;
    }
  }
  
  // 未找到可用的网络设备
  if(available_adapter_num == 0) {
    freeifaddrs(ifaddr);
    ifaddr = NULL;
    printf("No available network adapter\n");

    return -1; // failed to get adapter
  } else {
    printf("please enter 1 ~ %zu to choose a network adapter:  ", available_adapter_num);
    scanf("%zu", &choosed_adapter);
    choosed_adapter %= available_adapter_num; // avoid illegal input
    abs( choosed_adapter );
    if(choosed_adapter != 0) {
      choosed_adapter -= 1;
    } else {
      choosed_adapter = abs( available_adapter_num ) - 1;
    }
    
    // 存储用户选择的网络设备名
    memcpy(nic_info->nic_name, available_adapter_name[choosed_adapter], sizeof(nic_info->nic_name));
  }

  return 0;
}

//------function----------------------------------------------------------
// name: 
//    init_NIC_address
// description:
//    获取网络设备上的地址, ip, MAC, mask, 存储至 NIC_STRUCT structure
//----------------------------------------------------------------
int init_NIC_address(NIC_STRUCT *nic_info)
{
  struct ifreq ifr; // ifreq structure contains network interface infos
  char if_name[IFNAMSIZ] = "";
  memcpy(if_name, nic_info->nic_name, sizeof(if_name));
  unsigned char host_MAC[MAC_LENGTH] = ""; // Ethernet MAC address
  size_t if_name_len = strlen( if_name ); // ifr_name is a fixed-length buffer, be care about it
  int fd = socket(AF_UNIX, SOCK_DGRAM, 0); // function ioctl() need a socket descriptor as variable
  extern char *user_input_ipaddr;
  extern char *user_input_mask;

//
// Get the host( Ethernet interface )  MAC address in C
//
  if(fd == -1) {
    printf("%s", strerror(errno));
    printf("create socket failed\n");

    return -1;
  }
  if( if_name_len < sizeof( ifr.ifr_name ) ) {
    memcpy( ifr.ifr_name, if_name, if_name_len );
    ifr.ifr_name[if_name_len] = 0;
  } else {
    printf("interface name is too long");

    return -1;
  }

#if defined(DEBUG)
  printf("Network Interface Name: %s\n", ifr.ifr_name);
#endif

#ifdef SIOCGIFHWADDR
  // once have ifreq structure and socket descriptor then we can invoke ioctl()
  if ( ioctl( fd, SIOCGIFHWADDR, &ifr ) == -1 ) { 
    int temp_errno = errno;
    close( fd );
    printf("%s", strerror(temp_errno));
    printf(" get host MAC address procedure error\n");
    return -1;
  }
  close( fd );
  // make sure the type of the network interface we got is a Ethernet interface
  if ( ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER ) { 
    printf("not an Ethernet interface\n");

    return -1;
  }
  memcpy( host_MAC, ifr.ifr_hwaddr.sa_data, 6);
  memcpy(nic_info->nic_MAC, ifr.ifr_hwaddr.sa_data, MAC_LENGTH);
#endif
#if defined(DEBUG)
  printf("MAC address: %02X:%02X:%02X:%02X:%02X:%02X\n",
         host_MAC[0], host_MAC[1], host_MAC[2], host_MAC[3], host_MAC[4], host_MAC[5]);
#endif

//
// Get the IP address of a network interface in C using SIOCGIFADDR
//
  if(user_input_ipaddr == NULL) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in* ipaddr;
    if (fd == -1) {
      printf("%s", strerror(errno));

      return -1;
    }
#ifdef SIOCGIFADDR
    if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
      int temp_errno = errno;
      close(fd);
      printf("%s\n", strerror(temp_errno));
      printf("get ip address failed\n");

      return -1;
    }
    close(fd);
    ipaddr  = (struct sockaddr_in*)&ifr.ifr_addr;
    //nic_info->ipaddr = ipaddr->sin_addr.s_addr;
    memcpy(&nic_info->ipaddr, &ipaddr->sin_addr, sizeof(struct in_addr));
#endif
#if defined(DEBUG)
    printf("IP address: %s\n", inet_ntoa(ipaddr->sin_addr)); // ntoa : network to ASCII
#endif
  }
#if defined(DEBUG)
  printf("IP address: %s\n", user_input_ipaddr); // ntoa : network to ASCII
#endif

//
// Get the MASK address of a network interface in C using SIOCGIFNETMASK
//
  if(user_input_mask == NULL) {
    fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in* netmask;
    if(fd == -1) {
      printf("%s", strerror(errno));
      printf("create fd failed in GET MASK address function\n");

      return -1;
    }
#ifdef SIOCGIFNETMASK
    if(ioctl(fd, SIOCGIFNETMASK, &ifr) == -1) {
      int temp_errno = errno;
      close(fd);
      printf("%s\n", strerror(temp_errno));
      printf("get MASK address failed\n");

      return -1;
    }
    close(fd);
    netmask = (struct sockaddr_in*)&ifr.ifr_addr;
    //nic_info->netmask = netmask->sin_addr.s_addr;
    memcpy(&nic_info->netmask, &netmask->sin_addr, sizeof(struct in_addr));
#endif
#if defined(DEBUG)
    printf("Network Mask: %s\n", inet_ntoa(netmask->sin_addr));
#endif
  }
#if defined(DEBUG)
  printf("Network Mask: %s\n", user_input_mask);
#endif

  return 0;
}


static void PrintInitConfig()
{
  printf("\nUserName:\t%s\n", username);
  printf("Network Card:\t%s\n", nic_info.nic_name);
  printf("service name:\t%s\n\n\n", service_name);

  return;
}

