# jmuSupplicant

[![License](/l/rustc-serialize.svg)](https://raw.githubusercontent.com/ShanQincheng/jmuSupplicant/master/LICENSE)
/master/LICENSE.txt) 

这是一个适用于集美大学的第三方锐捷认证客户端。除了实现基础的认证并保持在线功能以外，额外实现了夜晚断网后认证功能。
普通认证支持所有服务类型的选择，夜晚断网后认证服务类型仅支持”教育网接入“。经测试，12:00p.m.后网速有较大提升，爱奇艺1080P勉强能够，抖音，Weibo毫无压力。

目前仅在 Ubuntu 17.10， 芯片为 mt7620 的路由器上测试并稳定运行。

## 正常使用方法

* 首先确保Linux系统安装了libpcap库
* make -f Makefile
* sudo ./jmuSupplicant.out -h 查看使用方法
* 推荐运行命令  sudo ./jmuSupplicant.out -u学号 -p密码 -s0(教育网接入)1(联通宽带接入)2(移动宽带接入)3(电信宽带接入) -b
* 程序输出锐捷认证信息，或显示 login success， 则认证成功。

## 断网后使用方法

* 首先自行找寻办公区域（夜晚能认证锐捷的地方，比如办公大楼）的ip地址，例如 123.456.789.123
* 推荐运行命令 sudo ./jmuSupplicant.out -u学号 -p密码 -s0 -b -n --ip 123.456.789.123
* 程序输出锐捷认证信息，或显示 login success， 则认证成功。

---

### License

Apache version 2.0
