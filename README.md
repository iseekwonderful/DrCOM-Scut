## Python版 scut drcom 认证

### 8月2日更新:
1. 去除`scapy`依赖, 方便在openwrt上运行, 只需要安装`python-simple`和`python-codec`, 和 `coreutils-nohup`包（大小在2.7M左右，如果你的flash是4M的话需要外挂u盘）.
2. 修复keep-alive问题。在C14测试稳定。

###  Warning:
1. macOS 不支持 python 2.7 的raw socket, 请使用scapy_example.py
2.  如果你的路由器的CPU是AR71XX或MT762X,请前往华工路由器群下载C版本，资源占用较Python版本较少，且有开发团队支撑
3.  Python版针对对`认证过程`感兴趣或路由器`奇葩CPU`的用户。

### 硬件配置：
Flash >= 8M 或 外挂U盘

### 安装配置：
1.   安装`openwrt`到路由器
2.   使用ssh登陆到openwrt(win下推荐`putty`, linux和osx直接ssh)
3.   更新openwrt包管理器: `opkg update`
4.   安装依赖项: `opkg install python-simple, python-codec, coreutils-nohup`. 如果是openwrt bb(14)及之前版本, 请安装`python-mini`, 即： `opkg install, python-mini python-codec, coreutils-nohup`(**未测试**)
5.   scp openwrt.py到路由器（以`/root`为例): `scp openwrt.py root@router_ip_address:~/` 将router_ip_address改为你的路由器ip即可。
6.   运行: python openwrt.py -u username -p password -i 接口
7.   第6步测试通过后, 使用 `nohup python openwrt.py -u username -p password -i 接口 &` 后台运行。(在openwrt上接口一般是eth0.1或者eth0.2)

### 资源占用: 
在NewWifi mini(MT7620, 128M RAM, 16M Flash)上:
	`6250  6196 root     S     7956   6%   0% python openwrt.py`
