# jmuSupplicant

[![License](https://img.shields.io/crates/l/rustc-serialize.svg)](https://raw.githubusercontent.com/ShanQincheng/jmuSupplicant/master/LICENSE)

这是一个适用于集美大学的第三方锐捷认证客户端。关于实现此客户端的实现过程，可以参考[锐捷认证过程分析与第三方锐捷认证客户端的设计与实现](https://github.com/ShanQincheng/jmuSupplicant/blob/master/doc/%E9%94%90%E6%8D%B7%E8%AE%A4%E8%AF%81%E8%BF%87%E7%A8%8B%E5%88%86%E6%9E%90%E4%B8%8E%E7%AC%AC%E4%B8%89%E6%96%B9%E9%94%90%E6%8D%B7%E8%AE%A4%E8%AF%81%E5%AE%A2%E6%88%B7%E7%AB%AF%E7%9A%84%E8%AE%BE%E8%AE%A1%E4%B8%8E%E5%AE%9E%E7%8E%B0.pdf)

除了实现基础的认证并保持在线功能以外，额外实现了夜晚断网后认证功能。

普通认证支持所有服务类型的选择，夜晚断网后认证服务类型仅支持“教育网接入”。

经测试，12:00 p.m.后网速有较大提升，爱奇艺 1080P 勉强能够，抖音，微博毫无压力。

# 编译

## 普通编译

首先请确保系统已安装 ```libpcap``` 库以及 ```CMake``` 。

```bash
git clone https://github.com/ShanQincheng/jmuSupplicant.git
cd jmuSupplicant
mkdir build
cd build
cmake ../
make
```

之后可以在 ```build/bin``` 目录下找到 jmuSupplicant 的可执行文件。

## 交叉编译

交叉编译需要先编译 libpcap ，之后再编译 jmuSupplicant。下面以交叉编译到 ar71xx 路由器为例：(以下代码中的一些参数需要根据你的实际情况做相应的修改，仅供参考)

### 获取目标设备的交叉编译工具链

从 [https://downloads.openwrt.org/](https://downloads.openwrt.org/) 上面下载目标设备的交叉编译工具链。例如 ar71xx 芯片的工具链下载地址为：[https://downloads.openwrt.org/releases/18.06.0/targets/ar71xx/generic/openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64.tar.xz](https://downloads.openwrt.org/releases/18.06.0/targets/ar71xx/generic/openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64.tar.xz)

(若下载缓慢，可以到[清华大学镜像源](https://mirrors.tuna.tsinghua.edu.cn/lede/)以及[中国科学技术大学镜像源](https://mirrors.ustc.edu.cn/lede/)下载相应工具链)

```bash
wget https://downloads.openwrt.org/releases/18.06.0/targets/ar71xx/generic/openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64.tar.xz
tar xvJf openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64.tar.xz
```

### 配置环境变量

环境变量中的具体路径以及参数要根据你的实际情况做相应的修改，以下代码仅供参考：

```bash
export PATH=$PATH:/home/xxx/openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl/bin
export CC=mips-openwrt-linux-gcc
export CPP=mips-openwrt-linux-cpp
export GCC=mips-openwrt-linux-gcc
export CXX=mips-openwrt-linux-g++
export RANLIB=mips-openwrt-linux-ranlib
export LC_ALL=C
export LDFLAGS="-static"
export CFLAGS="-Os -s"
export STAGING_DIR=/home/xxx/openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl
```

### 交叉编译 libpcap

```bash
wget http://www.tcpdump.org/release/libpcap-1.9.0.tar.gz
tar zxvf libpcap-1.9.0.tar.gz
cd libpcap-1.9.0
./configure --host=mips-linux --with-pcap=linux
make
```

如果交叉编译 libpcap 的过程中遇到错误，不用担心，这里我们只需要用到 ```libpcap.a``` ，编译后能得到该文件即可。之后将该文件以及 libpcap 的相关头文件复制到工具链的目录中：

```bash
cp libpcap.a /home/xxx/openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl/lib
cp pcap.h /home/xxx/openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl/include
cp -r pcap /home/xxx/openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl/include
```

### 交叉编译 jmuSupplicant

```bash
git clone https://github.com/ShanQincheng/jmuSupplicant.git
cd jmuSupplicant
mkdir build
cd build
cmake ../ -DCMAKE_FIND_ROOT_PATH=/home/xxx/openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY -DCMAKE_C_COMPILER=/home/xxx/openwrt-sdk-18.06.0-ar71xx-generic_gcc-7.3.0_musl.Linux-x86_64/staging_dir/toolchain-mips_24kc_gcc-7.3.0_musl/bin/mips-openwrt-linux-gcc
make
```

之后可以在 ```build/bin``` 目录下找到 jmuSupplicant 的可执行文件。

# 使用说明

可以通过```--help```参数来获取程序运行帮助，下面举例两种使用情况：

## 正常使用

- 使用以下指令进行锐捷认证：

  ```bash
  sudo ./jmu -u学号 -p密码 -s0(教育网接入)1(联通宽带接入)2(移动宽带接入)3(电信宽带接入) -b
  ```

- 程序输出锐捷认证信息，或显示 login success， 则认证成功。

## 断网后的使用

- 首先自行找寻办公区域（夜晚能认证锐捷的地方，比如办公大楼）的 IP 地址，例如：123.123.123.123

- 使用以下指令进行断网后的锐捷认证：

  ```bash
  sudo ./jmuSupplicant.out -u学号 -p密码 -s0 -b -n --ip 123.123.123.123
  ```

- 程序输出锐捷认证信息，或显示 login success， 则认证成功。

# 已测试稳定运行的设备

- 计算机：
  - Ubuntu 17.10
  - Archlinux 4.17.8-1-ARCH
- 路由器：
  - MT7620
  - ar71xx
- 其他：
  - 树莓派 2B

# License

Apache version 2.0
