#ifndef EX_CLIB_H
#define EX_CLIB_H

#include <stdint.h>
#include <arpa/inet.h>

//linux系统存放主机名信息的文件路径
//影响外部函数
#define SYS_HOSTS_CONF          "/etc/hosts"

//linux系统存放dns信息的文件路径
//影响函数get_sys_dns_string()
#define SYS_DNS_CONF 			"/etc/resolv.conf"

//linux系统网络设备信息列表的查询路径
//影响函数get_if_rtx()
#define SYS_PATH_PROCNET_DEV 	"/proc/net/dev"

//从一个网口设备上尝试读取最大的ip地址数量
//这里假设不会有什么应用会在一个网口配置4个以上的IP地址
//影响函数get_ipv4_ip_if_subnet_cmp()
#define SYS_NET_IF_IP_MAX		4

/*****************************************************************************************
函数参数:	char *name		接口名称
			int metric		跃点
			char *dst		目的地址
			char *gateway	网关
			char *genmask	子网掩码
函数功能:	添加路由与route命令相同
函数返回:	成功为0,失败非0
函数备注:
*****************************************************************************************/
//int route_add(char *name, int metric, char *dst, char *gateway, char *genmask);

/*****************************************************************************************
函数参数:	char *name		接口名称
			int metric		跃点
			char *dst		目的地址
			char *gateway	网关
			char *genmask	子网掩码
函数功能:	删除路由与route命令相同
函数返回:	成功为0,失败非0
函数备注:
*****************************************************************************************/
//int route_del(char *name, int metric, char *dst, char *gateway, char *genmask);

/*****************************************************************************************
函数参数:	const char *name接口名
			int flags		操作标志位IFUP
			char *addr		IP地址
			char *netmask	掩码
函数功能:	网络接口操作函数与ifconfig相同
函数返回:	成功为0,失败errno
函数备注:	若addr==NULL则代表删除接口上的IP地址
*****************************************************************************************/
#define IFUP (IFF_UP | IFF_RUNNING | IFF_BROADCAST | IFF_MULTICAST)
int ifconfig(const char *name, int flags, char *addr, char *netmask);

#ifndef HAS_LIBMACRO
/*****************************************************************************************
函数参数:	const void *src		存放数组格式的mac地址的缓冲区mac[6]={0xxx,0xxx,0xxx,0xxx,0xxx,0xxx}
			char *dst		输出字符格式的mac地址缓冲区xx:xx:xx:xx:xx:xx
			size_t size		输出缓冲区大小
函数功能:	将mac[6]={0xxx,0xxx,0xxx,0xxx,0xxx,0xxx}数组格式的mac地址转换为xx:xx:xx:xx:xx:xx字符串形式
函数返回:	成功为返回指针地址dst,失败返回NULL
函数备注:	函数内部默认src的空间为6
*****************************************************************************************/
const char *mac_ntop(const void *src,char *dst,size_t size);
#endif

/*****************************************************************************************
函数参数:	const char *s		存放字符格式的mac地址缓冲区xx:xx:xx:xx:xx:xx
			uint8_t *mac	输出数组格式的mac地址的缓冲区mac[6]={0xxx,0xxx,0xxx,0xxx,0xxx,0xxx}
函数功能:	将xx:xx:xx:xx:xx:xx字符串形式的mac地址转换为mac[6]={0xxx,0xxx,0xxx,0xxx,0xxx,0xxx}数组格式
函数返回:	成功返回1,失败返回0
函数备注:	mac_atoe和mac_pton都是实现该功能但是转换实现不一样
			mac_atoe使用strtoul函数实现字符16进制转数字
			mac_pton使用内部静态函数hex_to_bin实现字符16进制转数字
*****************************************************************************************/
uint8_t mac_atoe(const char *s,uint8_t *mac);
#ifndef HAS_LIBMACRO
uint8_t mac_pton(const char *s,uint8_t *mac);
#endif

/*****************************************************************************************
函数参数:	const char *ipv4		字符格式的掩码255.255.255.0
函数功能:	//255.255.255.x格式的掩码转换为数字形式
函数返回:	数字形式的掩码值,仅支持ipv4
函数备注:	传入非字符格式掩码的字符串结果无法预测
*****************************************************************************************/
int mask_ptoi(const char *ipv4);			

/*****************************************************************************************
函数参数:	const uint8_t *mac					要检测的MAC地址二进制格式{0xxx,0xxx,0xxx,0xxx,0xxx,0xxx}
			const char *mac					要检测的MAC地址字符串格式(XX:XX:XX:XX:XX:XX)
函数功能:	检测MAC地址正确性
函数返回:	成功为1,失败为0
函数备注:	is_mac支持数组格式的mac判断
			is_mac_string支持字符格式的mac判断
*****************************************************************************************/
int is_mac(const uint8_t *mac);
int is_mac_string(const char *mac);

/*****************************************************************************************
函数参数:	ipv4_str,ipv6_str,ipv4	,ipv6,ip	要检测的IP地址
			uint8_t can_empty				IP地址是否可以为空,如果可以(can_empty=1),那么当IP地址为空(全0)时,将返回1
函数功能:	检测IP地址正确性
函数返回:	成功为1,失败为0
函数备注:	is_valid_ipv4_string()检测IPV4地址字符格式正确性   (XXX.XXX.XXX.XXX)
			is_valid_ipv6_string()检测IPV6地址字符格式正确性   (XXXX::XXXX)
			is_valid_ipv4()检测IPv4地址正确性(struct in_addr)
			is_valid_ipv6()检测IPv6地址正确性(struct in6_addr)
			is_valid_ip()检测IP地址正确性(struct sockaddr_storage)
*****************************************************************************************/
int is_valid_ipv4_string(char *ipv4_str);
int is_valid_ipv6_string(char *ipv6_str);
int is_valid_ipv4(struct in_addr ipv4);
int is_valid_ipv6(struct in6_addr ipv6);
int is_valid_ip(struct sockaddr_storage ip,uint8_t can_empty);

/*****************************************************************************************
函数参数:	uint8_t mask		要检测的掩码值
函数功能:	检测IP地址掩码值得正确性
函数返回:	成功为1,失败为0
函数备注:	ipv4的正确掩码范围是1~32
			ipv6的正确掩码范围是1~128
			注:这里并没有包含0
*****************************************************************************************/
int is_valid_ipv4_mask(uint8_t mask);
int is_valid_ipv6_mask(uint8_t mask);

/*****************************************************************************************
函数参数:	const char *ifname			接口名
			char *mac				返回时存放MAC地址的缓冲区
函数功能:	从接口上获取字符格式的MAC地址(XX:XX:XX:XX:XX:XX)
函数返回:	成功为0地址,失败为errno
函数备注:
*****************************************************************************************/
int get_if_mac_str(const char *ifname,char *mac);

/*****************************************************************************************
函数参数:	const char *ifname			接口名
			int family					要获取的IP地址的协议族(AF_INET,AF_INET6)
			int index					地址索引,指定要获取接口上的第几个IP地址
			char *ip_strptr				返回时存放IP地址的缓冲区
			size_t ip_strptr_size		返回时存放IP地址的缓冲区大小
			uint8_t *netmask			获取到的IP地址的子网掩码(IPv4:0~32,IPV6:0~128)
函数功能:	从接口上获取IP地址
函数返回:	成功为ip_strptr地址,失败为NULL
函数备注:
*****************************************************************************************/
char *get_if_ip_string(const char *ifname,int family,int index, char *ip_strptr,size_t ip_strptr_size, uint8_t *netmask);//用于获取接口上的IP地址,返回为字符格式

/*****************************************************************************************
函数参数:	const char *ifname			接口名
			int index					地址索引,指定要获取接口上的第几个IP地址
			uint8_t *netmask			获取到的IP地址的子网掩码(IPv4:0~32,IPV6:0~128)
函数功能:	从接口上获取IP地址
函数返回:	成功为(struct in_addr)和(struct in6_addr)格式地址,失败返回赋值为全0的结构体
函数备注:	get_if_ipv4()返回的是ipv4地址
			get_if_ipv6()返回的是ipv6地址
*****************************************************************************************/
struct in_addr get_if_ipv4(const char *ifname,int index, uint8_t *netmask);
struct in6_addr get_if_ipv6(const char *ifname,int index, uint8_t *netmask);

/*****************************************************************************************
函数参数:	const char *ifname			接口名
			char *ip				存放IP地址的缓冲区,ipv4字符格式   (XXX.XXX.XXX.XXX)
函数功能:	获取PPPOE接口上对端IP地址,类似于网关地址
函数返回:	成功为0,失败返回errno
函数备注:	PPPOE接口上对端IP地址类似于网关
*****************************************************************************************/
int get_if_dst_ip(char *ifname,char *ip);

/*****************************************************************************************
函数参数:	const char *ifname			接口名
			char *ip				存放IP地址的缓冲区,ipv4字符格式   (XXX.XXX.XXX.XXX)
函数功能:	获取接口上的默认ipv4网关
函数返回:	成功为0,失败返回errno
函数备注:	函数取的是/proc/net/route中的内容,可能对格式有一定要求,特殊版本的linux如果格式变化,可能取不到预期值
*****************************************************************************************/
int get_if_route4_str(char *ifname,char *ip);

/*****************************************************************************************
函数参数:	const char *iface			接口名
函数功能:	获取接口上的默认ipv6网关
函数返回:	成功(struct in6_addr)格式地址,失败返回赋值为全0的结构体
函数备注:	函数取的是/proc/net/ipv6_route中的内容,可能对格式有一定要求,特殊版本的linux如果格式变化,可能取不到预期值
			代码参考自https://blog.csdn.net/y7u8t6/article/details/79531622
*****************************************************************************************/
struct in6_addr get_if_route6(const char *iface);	//用于获取接口第一个默认网关

/*****************************************************************************************
函数参数:	int family						要获取的DNS地址的协议族(AF_INET,AF_INET6,AF_INET46=0)
			int index					地址索引,指定要获取接口上的第几个DNS地址
			char *dns_strptr			返回时存放DNS地址的缓冲区,ipv4字符格式   (XXX.XXX.XXX.XXX)或ipv6地址字符格式   (XXXX::XXXX)
			size_t dns_strptr_size		返回时存放DNS地址的缓冲区大小
函数功能:	获取系统上配置的dns地址
函数返回:	成功为0,失败返回errno
函数备注:	函数取的是文件SYS_DNS_CONF=/etc/resolv.conf中的内容
			如果family=AF_INET将只能获取ipv4的dns地址,ipv6将被跳过
			如果family=AF_INET6将只能获取ipv6的dns地址,ipv4将被跳过
			如果family=AF_INET46=0能同时获取ipv4,ipv6的dns地址
*****************************************************************************************/
char *get_sys_dns_string(int family,int index,char *dns_strptr,size_t dns_strptr_size);

/*****************************************************************************************
函数参数:	const char *ifname				接口名
			net_device_stats *rtx_stats	存放数据的结构体
函数功能:	获取接口上的数据流量
函数返回:	成功为0,失败返回errno
函数备注:	函数读取的是SYS_PATH_PROCNET_DEV=/proc/net/dev定义的文件
*****************************************************************************************/
typedef struct net_device_stats {
    unsigned long long rx_packets;	/* total packets received       */
    unsigned long long tx_packets;	/* total packets transmitted    */
    unsigned long long rx_bytes;	/* total bytes received         */
    unsigned long long tx_bytes;	/* total bytes transmitted      */
}net_device_stats;
int get_if_rtx(char *ifname,net_device_stats *rtx_stats);

/*****************************************************************************************
函数参数:	uint8_t *mac				:存放mac地址的缓冲区mac[6]={0xxx,0xxx,0xxx,0xxx,0xxx,0xxx}数组格式
			char *ifname			:接口名,从哪个接口发起socket请求,仅get_mac_form_ipv4_by_socket_cache需要
			struct inx_addr ipv4_addr:需要获取对应mac地址的ipv4地址
函数功能:	通过给定的ipv4地址从系统arp缓冲链表中获取mac地址
函数返回:	成功为0,失败返回errno
函数备注:	mac这个地址,必须要有6字节以上的空间,函数内部不检测地址空间是否足够
			get_mac_form_ipv4_by_arp_cache通过读取/proc/net/arp的方式获取系统中的arp缓存
			get_mac_form_ipv4_by_socket_cache通过读取ioctl(SIOCGARP)的方式获取系统中的arp缓存
*****************************************************************************************/
int get_mac_form_ipv4_by_arp_cache(uint8_t *mac,struct in_addr ipv4_addr);
int get_mac_form_ipv4_by_socket_cache(uint8_t *mac,char *ifname,struct in_addr ipv4_addr);

/*****************************************************************************************
函数参数:	uint8_t *mac				:存放mac地址的缓冲区mac[6]={0xxx,0xxx,0xxx,0xxx,0xxx,0xxx}数组格式
			struct in6_addr ipv6_addr:需要获取对应mac地址的ipv6地址
函数功能:	通过给定的ipv6地址从系统ndp缓冲链表中获取mac地址
函数返回:	成功为0,失败返回errno
函数备注:	mac这个地址,必须要有6字节以上的空间,函数内部不检测地址空间是否足够
			通过读取/sbin/ip -6 neigh命令的返回结果获取系统中的ndp缓存
*****************************************************************************************/
int get_mac_form_ipv6_by_ndp_cache(uint8_t *mac,struct in6_addr ipv6_addr);

/*****************************************************************************************
函数参数:	uint8_t *dst_mac			:存放mac地址的缓冲区
			char *ifname			:请求arp的接口名称,该参数其实可以根据dst_ip,从路由表和ip addr上获取
			struct inx_addr src_ip	:请求arp的源ip地址信息,该参数其实可以根据dst_ip,从路由表和ip addr上获取
									 针对IPv6也可以选择填地址[::],但是未测试
			struct inx_addr dst_ip	:需要获取对应mac地址的ip地址
函数功能:	发送arp请求,从应答信息从提取mac地址
函数返回:	成功为0,失败返回errno
函数备注:	mac这个地址,必须要有6字节以上的空间,函数内部不检测地址空间是否足够
			ipv4的参考代码https://github.com/drkblog/findmacs
				模拟一次arp请求的发送,解析收到的包,调试发现这一过程后,系统的arp缓冲区并没有更新
				需要额外调用arp项添加函数,内部会额外调用静态函数set_mac_ipv4_to_arptable添加arp信息到系统
			ipv6的发送参考代码https://github.com/pearisgreen/c_samples/blob/master/src/ip/t8_nd_rd/ns.c
			ipv6的接收参考代码https://github.com/pearisgreen/c_samples/blob/master/src/ip/t8_nd_rd/receive_na.c
				非fe::的地址会额外做一次bind绑定,未测试这里的代码是否正常工作
			ipv6部分仍有搞不清楚的问题:
				单播地址似乎有误,需要查阅资料
				获得了全球地址的设备,无法使用对方的本地链路地址获得其mac地址
				ping6全球地址虽然能通,但是包发向了网关,网关了做了重定向,才能ping通设备
			极端条件下如果没有任何数据包返回,函数会阻塞100ms,由内部超时参数控制
*****************************************************************************************/
int get_mac_form_ipv4_by_arp_req(uint8_t *dst_mac,char *ifname,struct in_addr src_ip,struct in_addr dst_ip);
int get_mac_form_ipv6_by_ndp_req(uint8_t *dst_mac,char *ifname,struct in6_addr src_ip,struct in6_addr dst_ip);

/*****************************************************************************************
函数参数:	uint8_t prefixlen1				:前缀长度
函数功能:	给定前缀长度生成掩码地址
函数返回:	返回存放掩码的对应结构体in_addr),ipv6为(struct in6_addr)
函数备注:
*****************************************************************************************/
struct in_addr create_ipv4_mask(uint8_t prefixlen1); 
struct in6_addr create_ipv6_mask(uint8_t prefixlen1); 

/*****************************************************************************************
函数参数:	struct in6_addr ip_prefix		:ipv6地址1,用于头部
			struct in6_addr ip_tail		:ipv6地址2,用于尾部
			uint8_t prefixlen1
函数功能:	合并两个ip地址,通过前缀长度,将两个ipv6分别分割成前后部分,取ipv6地址1前半部分和ipv6地址2后半部分,拼接成一个新的地址
函数返回:	返回拼接后的地址
函数备注:	具体算法
			new_ip_head = ip_prefix & prefixlen1
			new_ip_tail = ip_tail & ~prefixlen1
			new_ip = new_ip_head + new_ip_tail
		这个函数应用场景不常见,仅用于特殊场合
*****************************************************************************************/
struct in6_addr get_ipv6_merge(struct in6_addr ip_prefix,struct in6_addr ip_tail,uint8_t prefixlen1);

/*****************************************************************************************
函数参数:	struct in_addr ip1		:IPv4网络地址
			uint8_t prefixlen1	:IPv4网络前缀长度值
函数功能:	根据提供的IPv4地址和前缀长度值计算IPV4地址的前缀(子网)
函数返回:	返回前缀地址
*****************************************************************************************/
struct in_addr get_ipv4_subnet_prefix(struct in_addr ip1,uint8_t prefixlen1);

/*****************************************************************************************
函数参数:	struct in6_addr ip1		:IPv6网络地址
			uint8_t prefixlen1		:IPv6网络前缀长度值
函数功能:	根据提供的IPv6地址和前缀长度值计算IPV6地址的前缀(子网)
函数返回:	返回前缀地址
*****************************************************************************************/
struct in6_addr get_ipv6_subnet_prefix(struct in6_addr ip1,uint8_t prefixlen1);

/*****************************************************************************************
函数参数:	struct in_addr ip1		:IPv4网络地址1
			struct in_addr ip2		:IPv4网络地址2
			uint8_t prefixlen1		:IPv4网络前缀长度值
函数功能:	根据提供的两个IPv4地址和前缀长度值计算是否属于同一子网
函数返回:	返回0表示属于同一子网,返回-1表示不属于
*****************************************************************************************/
int get_ipv4_subnet_cmp(struct in_addr ip1,struct in_addr ip2,uint8_t prefixlen1);

/*****************************************************************************************
函数参数:	struct in6_addr ip1		:IPv6网络地址1
			struct in6_addr ip2		:IPv6网络地址2
			uint8_t prefixlen1		:IPv6网络前缀长度值
函数功能:	根据提供的两个IPv6地址和前缀长度值计算是否属于同一子网
函数返回:	返回0表示属于同一子网,返回-1表示不属于
*****************************************************************************************/
int get_ipv6_subnet_cmp(struct in6_addr ip1,struct in6_addr ip2,uint8_t prefixlen1);

/*****************************************************************************************
函数参数:	struct in_addr ip1		:被检测IPV4地址
			const char *ifname		:被检测的接口名
			struct in_addr *cmp_ip	:命中的IP地址,可以送空指针
			uint8_t *cmp_mask		:命中的IP地址子网掩码,可以送空指针
函数功能:	检测IPV4地址是否属于该接口的子网
函数返回:	成功返回0,错误返回-1(不属于),-2(接口错误),-3(IP错误)
*****************************************************************************************/
int get_ipv4_ip_if_subnet_cmp(struct in_addr ip1,const char *ifname,struct in_addr *cmp_ip,uint8_t *cmp_mask);

#define AF_INET46 0
/*****************************************************************************************
函数参数:	int 						family		:转换家族类型0自动,AF_INET是ipv4,AF_INET6是ipv6
			const char 					*ip_str		:需要转换的字符串
			struct sockaddr_storage 	*addr_in46	:转换后的缓冲区
函数功能:	根据提供的字符串和参数,将其转换为struct sockaddr_storage数据结构
函数返回:	返回0参数错误
			返回1表示数据为空
			返回AF_INET表示字符串为ipv4地址,并且转换成功
			返回AF_INET6表示字符串为ipv6地址,并且转换成功
			返回-AF_INET表示字符串可能为ipv4地址,并且转换失败
			返回-AF_INET6表示字符串可能为ipv6地址,并且转换失败
*****************************************************************************************/
int inet46_pton(int family, const char *ip_str,struct sockaddr_storage *addr_in46);

/*****************************************************************************************
函数参数:	int 						family		:转换家族类型0自动,AF_INET是ipv4,AF_INET6是ipv6
			struct sockaddr_storage *addr_in46		:转换后的缓冲区
			const char *				ip_str		:需要转换的字符串
			size_t 					ip_strptr_size	:需要转换的字符串的缓冲区大小
函数功能:	根据提供的struct sockaddr_storage和参数,将其转换为字符串形式的IP地址
函数返回:	返回NULL转换错误
			返回存放字符串的首地址
*****************************************************************************************/
const char *inet46_ntop(int family,const struct sockaddr_storage *addr_in46, char *ip_strptr,size_t ip_strptr_size);

/*****************************************************************************************
函数参数:	const char *path	:文件位置字符串路径格式
函数功能:	返回给定的文件是否存在
函数返回:	1成功,0失败
函数备注:	内部使用库函数access来判断文件有效性
*****************************************************************************************/
uint8_t is_file_exist(const char *path);

/*****************************************************************************************
函数参数:	const char * pidfilename :PID文件名
函数功能:	确认指定的PID文件里的进程是否运行
函数返回:	如果小于0如下定于,大于0则是读取到的pid
函数备注:
*****************************************************************************************/
#define	LIBEXC_INVALID_ARGUMENT					-1
#define LIBEXC_OPEN_PID_FILE_ERR				-2
#define LIBEXC_OPEN_KILL_OPERATION_NOT_ALLOWED	-3
#define LIBEXC_KILL_NO_SUCH_PROCESS				-4
#define LIBEXC_NO_DATA_READ						-5
int read_pid_from_file(const char *pidfilename);

/*****************************************************************************************
函数参数:	int pid					:需要写入的PID值
			char *path				:PID文件名
函数功能:	将pid写入pid文件
函数返回:	系统errno
函数备注:
*****************************************************************************************/
int pid_to_file(int pid,char *path);

//字符串数据提取循环,例:"x  xx  xxx"以空格为分隔
//用法:
//	char item[ITEM_LEN];
//	char list[LIST_LEN]="x  xx  xxx";
//	char *next = NULL;
//	foreach(item,list,next)
//	{
//		printf("%s",item);
//	}
//
//输出结果:
//x
//xx
//xxx
#define foreach(word, wordlist, next) \
	for (next = &wordlist[strspn(wordlist, " ")], \
	     strncpy(word, next, sizeof(word)), \
	     word[strcspn(word, " ")] = '\0', \
	     word[sizeof(word) - 1] = '\0', \
	     next = strchr(next, ' '); \
	     strlen(word); \
	     next = next ? &next[strspn(next, " ")] : "", \
	     strncpy(word, next, sizeof(word)), \
	     word[strcspn(word, " ")] = '\0', \
	     word[sizeof(word) - 1] = '\0', \
	     next = strchr(next, ' '))

#endif

