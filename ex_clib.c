#include <stdio.h>
#include <stdlib.h>
#include <ctype.h> /* tolower() */
#include <errno.h>
#include <error.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <signal.h> /* for kill() */
//#ifdef GNU_LINUX
#define  __USE_GNU //解决struct in6_pktinfo的定义问题
//#endif
#ifndef __UCLIBC__
#include <ifaddrs.h>
#endif
#include <netdb.h> /* struct hostent */
#include <sys/ioctl.h>
#include <net/if.h>	/* for struct ifreq */
#include <net/if_arp.h>
#include <netinet/if_ether.h> /* for struct ether_arp */
#include <netinet/icmp6.h>
#include <netinet/ip.h> /* for IP_MAXPACKET */
#include <netinet/in.h> /* for struct in6_pktinfo */
#include <netpacket/packet.h> //#include <linux/if_packet.h> //#include <netpacket/packet.h>
#include <linux/if_ether.h>	/* for ETH_P_ARP ETH_P_IP ETH_P_IPV6 */
//#include <fcntl.h>
//#include <sys/stat.h>
//#include <sys/types.h>
//#include <sys/socket.h>
//#include <net/route.h>
//#include <arpa/inet.h>

#include "ex_clib.h"

/*****************************************************************************************
函数参数:	int cmd			路由操作命令
			char *name		接口名
			int metric		跃点值
			char *dst		目的地址
			char *gateway	网关地址
			char *genmask	子网掩码
函数功能:	添加或删除路由
函数返回:	成功为0,失败errno
函数备注:
static int route_manip(int cmd, char *name, int metric, char *dst, char *gateway, char *genmask);
*****************************************************************************************/

#define sin_addr(s) (((struct sockaddr_in *)(s))->sin_addr)

int ifconfig(const char *name, int flags, char *addr, char *netmask)
{
	int s;
	struct ifreq ifr;
	struct in_addr in_addr, in_netmask, in_broadaddr;

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
		goto err;

	strncpy(ifr.ifr_name, name, IFNAMSIZ);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

	ifr.ifr_flags = flags;
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0)
		goto err;

	if (addr) {
		inet_aton(addr, &in_addr);
		sin_addr(&ifr.ifr_addr).s_addr = in_addr.s_addr;
		ifr.ifr_addr.sa_family = AF_INET;
		if (ioctl(s, SIOCSIFADDR, &ifr) < 0)
			goto err;
	}

	if (addr && netmask) {
		inet_aton(netmask, &in_netmask);
		sin_addr(&ifr.ifr_netmask).s_addr = in_netmask.s_addr;
		ifr.ifr_netmask.sa_family = AF_INET;
		if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0)
			goto err;

		in_broadaddr.s_addr = (in_addr.s_addr & in_netmask.s_addr) | ~in_netmask.s_addr;
		sin_addr(&ifr.ifr_broadaddr).s_addr = in_broadaddr.s_addr;
		ifr.ifr_broadaddr.sa_family = AF_INET;
		if (ioctl(s, SIOCSIFBRDADDR, &ifr) < 0)
			goto err;
	}

	close(s);
	return 0;

 err:
	close(s);
	perror(name);
	return errno;
}
/*
static int route_manip(int cmd, char *name, int metric, char *dst, char *gateway, char *genmask)
{
	int s;
	struct rtentry rt;

	if ((s = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
		goto err;

	memset(&rt, 0, sizeof(rt));
	if (dst)
		inet_aton(dst, &sin_addr(&rt.rt_dst));
	if (gateway)
		inet_aton(gateway, &sin_addr(&rt.rt_gateway));
	if (genmask)
		inet_aton(genmask, &sin_addr(&rt.rt_genmask));
	rt.rt_metric = metric;
	rt.rt_flags = RTF_UP;
	if (sin_addr(&rt.rt_gateway).s_addr)
		rt.rt_flags |= RTF_GATEWAY;
	if (sin_addr(&rt.rt_genmask).s_addr == INADDR_BROADCAST)
		rt.rt_flags |= RTF_HOST;
	rt.rt_dev = name;

	rt.rt_dst.sa_family = AF_INET;
	rt.rt_gateway.sa_family = AF_INET;
	rt.rt_genmask.sa_family = AF_INET;

	if (ioctl(s, cmd, &rt) < 0)
		goto err;

	close(s);
	return 0;

 err:
	close(s);
	perror(name);
	return errno;
}

int route_add(char *name, int metric, char *dst, char *gateway, char *genmask)
{
	return route_manip(SIOCADDRT, name, metric, dst, gateway, genmask);
}

int route_del(char *name, int metric, char *dst, char *gateway, char *genmask)
{
	return route_manip(SIOCDELRT, name, metric, dst, gateway, genmask);
}
*/

int get_ipv6_prefix_len(struct in6_addr *mask)
{
    uint8_t i = 0;
    uint8_t len = 0;
    uint8_t u = 0;
    for(i = 0; i < 16; i++)
    {
        u = mask->s6_addr[i];
        if(ffs(u) > 0)
        {
            len += 9 - ffs(u);
        }
        else
        {
            break;
        }
    }
    return len;
}

int get_ipv4_prefix_len(struct in_addr *mask)
{
    uint8_t len = 0;
    u_long u = 0;

    u = htonl(mask->s_addr);
    if(ffs(u) > 0)
    {
        len += 33 - ffs(u);
    }

    return len;
}
#ifndef _IFADDRS_H
char *get_if_ip_string(const char *ifname,int family,int index, char *ip_strptr,size_t ip_strptr_size, uint8_t *netmask)
{
	if(ifname == NULL || ip_strptr == NULL)
		return NULL;

	switch (family)
	{
		case AF_INET:
		{
			if(0 == index)
			{//不支持多IP
				/* use ioctl SIOCGIFADDR. Works only for ip v4 */
				/* SIOCGIFADDR struct ifreq *  */
				int s;
				struct ifreq ifr;
				int ifrlen;
				struct sockaddr_in *addr_in;
				ifrlen = sizeof(ifr);

				if(!ifname || ifname[0] == '\0')
					return NULL;

				s = socket(PF_INET, SOCK_DGRAM, 0);
				if(s < 0)
				{
					syslog(LOG_ERR,"%s()->socket(PF_INET, SOCK_DGRAM)err -> %s",__FUNCTION__,strerror(errno));
					return NULL;
				}
				//获取接口up/down的状态
				strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
				ifr.ifr_name[IFNAMSIZ-1] = '\0';
				if(ioctl(s,SIOCGIFFLAGS, &ifr, &ifrlen) < 0)
				{
					syslog(LOG_ERR,"%s()->ioctl(SIOCGIFFLAGS)err -> %s",__FUNCTION__,strerror(errno));
					close(s);
					return NULL;
				}
				if ((ifr.ifr_flags & IFF_UP) == 0)
				{
					syslog(LOG_DEBUG, "%s()network interface %s is down",__FUNCTION__,ifname);
					close(s);
					return NULL;
				}
				//获取接口IP地址
				strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
				ifr.ifr_name[IFNAMSIZ-1] = '\0';
				if(ioctl(s, SIOCGIFADDR, &ifr, &ifrlen) < 0)
				{
					syslog(LOG_ERR,"%s()->ioctl(SIOCGIFADDR)err -> %s",__FUNCTION__,strerror(errno));
					close(s);
					return NULL;
				}
				addr_in = (struct sockaddr_in *)&ifr.ifr_addr;
				if(addr_in)
				{
					if(inet_ntop(AF_INET,&addr_in->sin_addr,ip_strptr,ip_strptr_size) == NULL)
					{
						syslog(LOG_ERR,"%s() addr_in to string error -> %s\n",__FUNCTION__,strerror(errno));
						strcpy(ip_strptr,"");//出错设置为空
					}
				}
				if(netmask)
				{
					strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
					ifr.ifr_name[IFNAMSIZ-1] = '\0';
					if(ioctl(s, SIOCGIFNETMASK, &ifr, &ifrlen) < 0)
					{
						syslog(LOG_ERR,"%s()->ioctl(SIOCGIFNETMASK)err -> %s",__FUNCTION__,strerror(errno));
						close(s);
						return NULL;
					}
					addr_in = ((struct sockaddr_in *)&ifr.ifr_netmask);
					if(addr_in)
					{
						*netmask = get_ipv4_prefix_len(&addr_in->sin_addr);
					}
					syslog(LOG_DEBUG,"%s() test get ifname = %s,ip %s/%d\n",__FUNCTION__,ifname,ip_strptr,*netmask);
				}
				else
				{
					syslog(LOG_DEBUG,"%s() test get ifname = %s,ip %s\n",__FUNCTION__,ifname,ip_strptr);
				}
				close(s);
			}
			break;
		}
		case AF_INET6:
		{
			//暂不支持
			break;
		}
		default:
			break;
	}

	return NULL;
}

struct in_addr get_if_ipv4(const char *ifname,int index, uint8_t *netmask)
{
	struct in_addr in_addr_ret;
	in_addr_ret.s_addr = INADDR_ANY;

	if(index == 0)
	{//不支持多IP
		/* use ioctl SIOCGIFADDR. Works only for ip v4 */
		/* SIOCGIFADDR struct ifreq *  */
		int s;
		struct ifreq ifr;
		int ifrlen;
		struct sockaddr_in *addr_in;
		ifrlen = sizeof(ifr);

		if(!ifname || ifname[0] == '\0')
			return in_addr_ret;

		s = socket(PF_INET, SOCK_DGRAM, 0);
		if(s < 0)
		{
			syslog(LOG_ERR,"%s()->socket(PF_INET, SOCK_DGRAM)err -> %s",__FUNCTION__,strerror(errno));
			return in_addr_ret;
		}
		//获取接口up/down的状态
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		ifr.ifr_name[IFNAMSIZ-1] = '\0';
		if(ioctl(s,SIOCGIFFLAGS, &ifr, &ifrlen) < 0)
		{
			syslog(LOG_ERR,"%s()->ioctl(SIOCGIFFLAGS)err -> %s",__FUNCTION__,strerror(errno));
			close(s);
			return in_addr_ret;
		}
		if ((ifr.ifr_flags & IFF_UP) == 0)
		{
			syslog(LOG_DEBUG, "%s()network interface %s is down",__FUNCTION__,ifname);
			close(s);
			return in_addr_ret;
		}
		//获取接口IP地址
		strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
		ifr.ifr_name[IFNAMSIZ-1] = '\0';
		if(ioctl(s, SIOCGIFADDR, &ifr, &ifrlen) < 0)
		{
			syslog(LOG_ERR,"%s()->ioctl(SIOCGIFADDR)err -> %s",__FUNCTION__,strerror(errno));
			close(s);
			return in_addr_ret;
		}

		addr_in = (struct sockaddr_in *)&ifr.ifr_addr;
		if(addr_in && is_valid_ipv4(addr_in->sin_addr))
		{
			char ip_addr_char1[64] = {0};
			in_addr_ret = addr_in->sin_addr;
			if(netmask)
			{
				strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
				ifr.ifr_name[IFNAMSIZ-1] = '\0';
				if(ioctl(s, SIOCGIFNETMASK, &ifr, &ifrlen) < 0)
				{
					syslog(LOG_ERR,"%s()->ioctl(SIOCGIFNETMASK)err -> %s",__FUNCTION__,strerror(errno));
					close(s);
					return in_addr_ret;
				}
				addr_in = ((struct sockaddr_in *)&ifr.ifr_netmask);
				if(addr_in)
					*netmask = get_ipv4_prefix_len(&addr_in->sin_addr);
			}
			if(inet_ntop(AF_INET,&in_addr_ret,ip_addr_char1,sizeof(ip_addr_char1)))
			{
				if(netmask)
					syslog(LOG_DEBUG,"%s() test get ifname = %s,ipv4 %s/%d\n",__FUNCTION__,ifname,ip_addr_char1,*netmask);
				else
					syslog(LOG_DEBUG,"%s() test get ifname = %s,ipv4 %s\n",__FUNCTION__,ifname,ip_addr_char1);
			}
		}
		close(s);
	}

	return in_addr_ret;
}

struct in6_addr get_if_ipv6(const char *ifname,int index, uint8_t *netmask)
{
	struct in6_addr in6_addr_ret = in6addr_any;
	//暂不支持
	return in6_addr_ret;
}
#else
char *get_if_ip_string(const char *ifname,int family,int index, char *ip_strptr,size_t ip_strptr_size, uint8_t *netmask)
{
	struct ifaddrs *ifaddrlist,*ifaddrlist_bak;
	int index_count = 0;
	char iface2[IFNAMSIZ];

	if(ifname == NULL || ip_strptr == NULL)
		return NULL;

	if(getifaddrs(&ifaddrlist_bak) != 0)
		return NULL;

	snprintf(iface2,sizeof(iface2),"%s:",ifname);

	for(ifaddrlist = ifaddrlist_bak;ifaddrlist!=NULL;ifaddrlist=(*ifaddrlist).ifa_next)
	{
		if((*ifaddrlist).ifa_addr)
		{
			if(((*ifaddrlist).ifa_addr)->sa_family != family)
			{
				continue;
			}
		}
		else
		{
			continue;
		}

		if((strcmp((*ifaddrlist).ifa_name,ifname) == 0 || (strstr((*ifaddrlist).ifa_name,iface2) != NULL)) && (*ifaddrlist).ifa_addr)
		{
			switch (((*ifaddrlist).ifa_addr)->sa_family)
			{
				case AF_INET:
				{
					if(index_count == index)
					{
						struct sockaddr_in *addr_in = (struct sockaddr_in *) (*ifaddrlist).ifa_addr;
						//if(addr_in)//前面已经判断
						if(inet_ntop(AF_INET,&addr_in->sin_addr,ip_strptr,ip_strptr_size) == NULL)
						{
							syslog(LOG_ERR,"%s() addr_in to string error -> %s\n",__FUNCTION__,strerror(errno));
							strcpy(ip_strptr,"");//出错设置为空
						}
						addr_in = (struct sockaddr_in *) (*ifaddrlist).ifa_netmask;
						if(addr_in && netmask)*netmask = get_ipv4_prefix_len(&addr_in->sin_addr);
						if(netmask)
							syslog(LOG_DEBUG,"%s() test get ifname = %s,ip %s/%d\n",__FUNCTION__,(*ifaddrlist).ifa_name,ip_strptr,*netmask);
						else
							syslog(LOG_DEBUG,"%s() test get ifname = %s,ip %s\n",__FUNCTION__,(*ifaddrlist).ifa_name,ip_strptr);
						goto get_ip_ok;
					}
					else
					{
						index_count++;
					}
					break;
				}
				case AF_INET6:
				{
					if(index_count == index)
					{
						struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) (*ifaddrlist).ifa_addr;
						//if(addr_in)//前面已经判断
						if(inet_ntop(AF_INET6,&addr_in6->sin6_addr,ip_strptr,ip_strptr_size) == NULL)
						{
							syslog(LOG_ERR,"%s() addr_in6 to string error -> %s\n",__FUNCTION__,strerror(errno));
							strcpy(ip_strptr,"");//出错设置为空
						}
						addr_in6 = (struct sockaddr_in6 *) (*ifaddrlist).ifa_netmask;
						if(addr_in6 && netmask)*netmask = get_ipv6_prefix_len(&addr_in6->sin6_addr);
						if(netmask)
							syslog(LOG_DEBUG,"%s() test get ifname = %s,ip %s/%d\n",__FUNCTION__,(*ifaddrlist).ifa_name,ip_strptr,*netmask);
						else
							syslog(LOG_DEBUG,"%s() test get ifname = %s,ip %s\n",__FUNCTION__,(*ifaddrlist).ifa_name,ip_strptr);
						goto get_ip_ok;
					}
					else
					{
						index_count++;
					}
					break;
				}
				default:
					break;
			}
		}
	}
	freeifaddrs(ifaddrlist_bak);
	return NULL;
get_ip_ok:
	freeifaddrs(ifaddrlist_bak);
	return ip_strptr;
}

struct in_addr get_if_ipv4(const char *ifname,int index, uint8_t *netmask)
{
	struct ifaddrs *ifaddrlist,*ifaddrlist_bak;
	int index_count = 0;
	char iface2[IFNAMSIZ];
	struct in_addr in_addr_ret;
	in_addr_ret.s_addr = INADDR_ANY;

	if(ifname == NULL)
		return in_addr_ret;

	if(getifaddrs(&ifaddrlist_bak) != 0)
		return in_addr_ret;

	snprintf(iface2,sizeof(iface2),"%s:",ifname);

	for(ifaddrlist = ifaddrlist_bak;ifaddrlist!=NULL;ifaddrlist=(*ifaddrlist).ifa_next)
	{
		if((strcmp((*ifaddrlist).ifa_name,ifname) == 0 || (strstr((*ifaddrlist).ifa_name,iface2) != NULL)) && (*ifaddrlist).ifa_addr)
		{
			if (((*ifaddrlist).ifa_addr)->sa_family == AF_INET)
			{
				if(index_count == index)
				{
					struct sockaddr_in *addr_in = (struct sockaddr_in *) (*ifaddrlist).ifa_addr;
					if(addr_in && is_valid_ipv4(addr_in->sin_addr))
					{
						in_addr_ret = addr_in->sin_addr;
						addr_in = (struct sockaddr_in *) (*ifaddrlist).ifa_netmask;
						if(netmask && addr_in)
						{
							*netmask = get_ipv4_prefix_len(&addr_in->sin_addr);
						}
						if(netmask)
						{
							char ip_addr_char1[64] = {0};
							if(inet_ntop(AF_INET,&in_addr_ret,ip_addr_char1,sizeof(ip_addr_char1)))
							{
								syslog(LOG_DEBUG,"%s() test get ifname = %s,ipv4 %s/%d\n",__FUNCTION__,(*ifaddrlist).ifa_name,ip_addr_char1,*netmask);
							}
						}
						break;
					}
				}
				else
				{
					index_count++;
				}
			}
		}
	}
	freeifaddrs(ifaddrlist_bak);
	return in_addr_ret;
}

struct in6_addr get_if_ipv6(const char *ifname,int index, uint8_t *netmask)
{
	struct ifaddrs *ifaddrlist,*ifaddrlist_bak;
	int index_count = 0;
	char iface2[IFNAMSIZ];
	struct in6_addr in6_addr_ret = in6addr_any;

	if(ifname == NULL)
		return in6_addr_ret;

	if(getifaddrs(&ifaddrlist_bak) != 0)
		return in6_addr_ret;

	snprintf(iface2,sizeof(iface2),"%s:",ifname);

	for(ifaddrlist = ifaddrlist_bak;ifaddrlist!=NULL;ifaddrlist=(*ifaddrlist).ifa_next)
	{
		if((strcmp((*ifaddrlist).ifa_name,ifname) == 0 || (strstr((*ifaddrlist).ifa_name,iface2) != NULL)) && (*ifaddrlist).ifa_addr)
		{
			if (((*ifaddrlist).ifa_addr)->sa_family == AF_INET6)
			{
				if(index_count == index)
				{
					struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *) (*ifaddrlist).ifa_addr;
					if(addr_in6 && is_valid_ipv6(addr_in6->sin6_addr))
					{
						in6_addr_ret = addr_in6->sin6_addr;
						addr_in6 = (struct sockaddr_in6 *) (*ifaddrlist).ifa_netmask;
						if(netmask && addr_in6)
						{
							*netmask = get_ipv6_prefix_len(&addr_in6->sin6_addr);
						}
						if(netmask)
						{
							char ip_addr_char1[64] = {0};
							if(inet_ntop(AF_INET6,&in6_addr_ret,ip_addr_char1,sizeof(ip_addr_char1)))
							{
								syslog(LOG_DEBUG,"%s() test get ifname = %s,ipv6 %s/%d\n",__FUNCTION__,(*ifaddrlist).ifa_name,ip_addr_char1,*netmask);
							}
						}
						break;
					}
				}
				else
				{
					index_count++;
				}
			}
		}
	}
	freeifaddrs(ifaddrlist_bak);
	return in6_addr_ret;
}
#endif

int get_if_dst_ip(char *ifname,char *ip)
{
	struct ifreq ifr;
	int s ;

	if(ifname == NULL)
	{
		return EINVAL;
	}
	if(ip == NULL)
	{
		return EINVAL;
	}

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		perror(ifname);
		return errno;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

	if (ioctl(s, SIOCGIFDSTADDR, &ifr))
	{
		perror(ifname);
		close(s);
		return errno;
	}

	strcpy(ip,inet_ntoa(sin_addr(&ifr.ifr_dstaddr)));
	close(s);
	return 0;
}

int get_if_mac_str(const char * ifname,char *mac)
{
	struct ifreq ifr;
	int s ;

	if(ifname == NULL)
	{
		return EINVAL;
	}
	if(mac == NULL)
	{
		return EINVAL;
	}

	if ((s = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0)
	{
		perror(ifname);
		return errno;
	}

	strncpy(ifr.ifr_name, ifname, IFNAMSIZ);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

	if (ioctl(s, SIOCGIFHWADDR, &ifr))
	{
		perror(ifname);
		close(s);
		return errno;
	}
	sprintf(mac,"%02x:%02x:%02x:%02x:%02x:%02x",(uint8_t)ifr.ifr_hwaddr.sa_data[0],(uint8_t)ifr.ifr_hwaddr.sa_data[1],(uint8_t)ifr.ifr_hwaddr.sa_data[2],(uint8_t)ifr.ifr_hwaddr.sa_data[3],(uint8_t )ifr.ifr_hwaddr.sa_data[4],(uint8_t )ifr.ifr_hwaddr.sa_data[5]);
	close(s);
	return 0;
}

int get_if_route4_str(char *ifname,char *ip)
{
	char buff[256];
	int  nl = 0 ;
	struct in_addr dest;
	struct in_addr gw;
	int flgs, ref, use, metric;
	unsigned long int d,g,m;
	FILE *fp;

	if(ifname == NULL)
	{
		return EINVAL;
	}
	if(ip == NULL)
	{
		return EINVAL;
	}

	strcpy(ip,"0.0.0.0");

	if((fp = fopen("/proc/net/route", "r")) == NULL)
	{
		perror(ifname);
		return -1;
	}

	while(fgets(buff, sizeof(buff), fp) != NULL)
	{
		if(nl)
		{
			int ifl = 0;
			while(buff[ifl]!=' ' && buff[ifl]!='\t' && buff[ifl]!='\0')ifl++;
			buff[ifl]=0;    /* interface */
			if(sscanf(buff+ifl+1, "%lx%lx%d%d%d%d%lx",&d, &g, &flgs, &ref, &use, &metric, &m)!=7)
			{
				syslog(LOG_WARNING,"%s Unsuported kernel route format\n",__FUNCTION__);
			}

			dest.s_addr = d;
			gw.s_addr   = g;
			if(dest.s_addr==0 && gw.s_addr!=0 && strcmp(ifname,buff) == 0)
			{
				strcpy(ip,inet_ntoa(gw));
				fclose(fp);
				return 0;
			}
		}
		nl++;
	}
	fclose(fp);
	return -2;
}

struct in6_addr get_if_route6(const char *iface)
{
	struct in6_addr ret = in6addr_any;
	FILE *fp;
	char dst_addr_char[64] = {0};
	char dst_mask_char[64] = {0};
	char src_addr_char[64] = {0};
	char src_mask_char[64] = {0};
    char gw_addr_char[8][5] = {{0}};
    char metric_char[64] = {0};
	char refcnt_char[64] = {0};
    char use_char[64] = {0};
    char flags_char[64] = {0};
    char route_iface[64] = {0};
	char ip_addr_char1[64] = {0};

	if(iface == NULL)
	{
		return ret;
	}

	if((fp = fopen("/proc/net/ipv6_route", "r")) == NULL)
	{
		syslog(LOG_ERR, "Can't open file %s error -> %s\n","/proc/net/ipv6_route",strerror(errno));
		return ret;
	}
    lockf(fileno(fp), F_LOCK, 0);
	while(fscanf(fp, "%s %02s %s %s %4s%4s%4s%4s%4s%4s%4s%4s %s %s %s %s %20s\n",
		dst_addr_char, dst_mask_char, src_addr_char, src_mask_char,
		gw_addr_char[0], gw_addr_char[1], gw_addr_char[2], gw_addr_char[3],
		gw_addr_char[4], gw_addr_char[5], gw_addr_char[6], gw_addr_char[7],
		metric_char, refcnt_char, use_char, flags_char, route_iface) != EOF)
	{
		if (!strcmp(route_iface, iface) && atoi(dst_mask_char) == 0)
		{
			sprintf(ip_addr_char1, "%s:%s:%s:%s:%s:%s:%s:%s",gw_addr_char[0], gw_addr_char[1], gw_addr_char[2], gw_addr_char[3],gw_addr_char[4], gw_addr_char[5], gw_addr_char[6], gw_addr_char[7]);
			if(inet_pton(AF_INET6, ip_addr_char1, &ret) <= 0)
			{
				syslog(LOG_ERR,"%s() ipv6 gw get unkown string %s\n",__FUNCTION__,ip_addr_char1);
				ret = in6addr_any;
			}
			break;
		}
	}
    lockf(fileno(fp), F_ULOCK, 0);
	fclose(fp);
	return ret;
}

char *get_sys_dns_string(int family,int index,char *dns_strptr,size_t dns_strptr_size)
{
	FILE *fp;

	if(dns_strptr == NULL)
	{
		return NULL;
	}

	if(family != AF_INET && family != AF_INET6 && family != AF_INET46)
	{
		return NULL;
	}

	if((fp = fopen(SYS_DNS_CONF,"rb")) == NULL)
	{
		return NULL;
	}
	else
	{
		char	read_buf[128];
		int		find_index = 0;
		char	*ret_char = NULL;
		while(NULL != fgets(read_buf,sizeof(read_buf),fp))//获得一行数据
		{
			char *nameserver_str = strstr(read_buf,"nameserver ");
			if(nameserver_str != NULL)
			{
				//nameserver 4.2.2.2\n
				char *tmp=strchr(nameserver_str,'\n');
				if(tmp)*tmp = '\0';//消除行尾换行
				//nameserver 4.2.2.2
				nameserver_str += strlen("nameserver ");
				//4.2.2.2
				if(is_valid_ipv4_string(nameserver_str) && (family == AF_INET || family == AF_INET46))
				{
					if(find_index == index)
					{
						snprintf(dns_strptr,dns_strptr_size,"%s",nameserver_str);
						ret_char = dns_strptr;
						break;
					}
					else
					{
						find_index++;
					}
				}
				else if(is_valid_ipv6_string(nameserver_str) && (family == AF_INET6 || family == AF_INET46))
				{
					if(find_index == index)
					{
						snprintf(dns_strptr,dns_strptr_size,"%s",nameserver_str);
						ret_char = dns_strptr;
						break;
					}
					else
					{
						find_index++;
					}
				}
				else
				{
					syslog(LOG_DEBUG,"%s get unkown dns string %s\n",__FUNCTION__,nameserver_str);
				}
			}
		}
		fclose(fp);
		return ret_char;
	}
	return NULL;
}

struct user_net_device_stats {//网络接口状态数据定义(系统 第三版)
    unsigned long long rx_packets;	/* total packets received       */
    unsigned long long tx_packets;	/* total packets transmitted    */
    unsigned long long rx_bytes;	/* total bytes received         */
    unsigned long long tx_bytes;	/* total bytes transmitted      */
    unsigned long rx_errors;	/* bad packets received         */
    unsigned long tx_errors;	/* packet transmit problems     */
    unsigned long rx_dropped;	/* no space in linux buffers    */
    unsigned long tx_dropped;	/* no space available in linux  */
    unsigned long rx_multicast;	/* multicast packets received   */
    unsigned long rx_compressed;
    unsigned long tx_compressed;
    unsigned long collisions;
    /* detailed rx_errors: */
    unsigned long rx_length_errors;
    unsigned long rx_over_errors;	/* receiver ring buff overflow  */
    unsigned long rx_crc_errors;	/* recved pkt with crc error    */
    unsigned long rx_frame_errors;	/* recv'd frame alignment error */
    unsigned long rx_fifo_errors;	/* recv'r fifo overrun          */
    unsigned long rx_missed_errors;	/* receiver missed packet     */
    /* detailed tx_errors */
    unsigned long tx_aborted_errors;
    unsigned long tx_carrier_errors;
    unsigned long tx_fifo_errors;
    unsigned long tx_heartbeat_errors;
    unsigned long tx_window_errors;
};

int get_if_rtx(char *ifname,net_device_stats *rtx_stats)
{
	struct user_net_device_stats stats;
	FILE *fp;
	int i = 0;
	int j = 0;
	int k = 0;
	char *if_dns;
	char turn[100] = "";
	char buf[512];

	if(ifname == NULL)
	{
		return EINVAL;
	}
	if(rtx_stats == NULL)
	{
		return EINVAL;
	}

	if((fp = fopen(SYS_PATH_PROCNET_DEV,"r")) == NULL)
	{
		syslog(LOG_ERR,"%s() Can't open file %s -> %s",__FUNCTION__,SYS_PATH_PROCNET_DEV,strerror(errno));
		return errno;
	}

	while(NULL != fgets(buf,512,fp))
	{
		k = 0;
		if(ifname == NULL)
			break;
		if_dns = strchr(buf,':');
		if(if_dns == NULL)
			continue;
		else
		{
			while((int)*if_dns != 32)
			{
				k ++;
				if_dns--;
			}
		}
		for(j=0;j<(k-1);j++)
		{
			turn[j] = if_dns[j+1];
		}
		turn[k-1] = '\0';

		if(strcmp(turn,ifname) != 0)
		{
			continue;
		}
		else
		{
			sscanf(strchr(buf,':')+1,"%Lu %Lu %lu %lu %lu %lu %lu %lu %Lu %Lu %lu %lu %lu %lu %lu %lu",
				&stats.rx_bytes,
				&stats.rx_packets,
				&stats.rx_errors,
				&stats.rx_dropped,
				&stats.rx_fifo_errors,
				&stats.rx_frame_errors,
				&stats.rx_compressed,
				&stats.rx_multicast,
				&stats.tx_bytes,
				&stats.tx_packets,
				&stats.tx_errors,
				&stats.tx_dropped,
				&stats.tx_fifo_errors,
				&stats.collisions,
				&stats.tx_carrier_errors,
				&stats.tx_compressed);

			rtx_stats->rx_bytes		= stats.rx_bytes;
			rtx_stats->tx_bytes		= stats.tx_bytes;
			rtx_stats->rx_packets	= stats.rx_packets;
			rtx_stats->tx_packets	= stats.tx_packets;
			i++;
			break;
		}
	}
	fclose(fp);
	if(i == 0)
		return -2;	//表示读取失败
	else
		return 0;	//表示读取成功
}

int is_valid_ipv4(struct in_addr ip)
{
	if(ip.s_addr == htonl(INADDR_ANY))
	{
		return 0;
	}
    return 1;
}

int is_valid_ipv6(struct in6_addr ip)
{
	if(IN6_IS_ADDR_UNSPECIFIED(&ip))
	{
		return 0;
	}
    return 1;
}

int is_valid_ip(struct sockaddr_storage check_ip,uint8_t can_empty)
{
	char ip_addr_char1[64] = {0};

	if(check_ip.ss_family == AF_INET)
	{
		struct sockaddr_in *addr_in = (struct sockaddr_in *)&check_ip;
		if(inet_ntop(AF_INET,&addr_in->sin_addr,ip_addr_char1,sizeof(ip_addr_char1)) == NULL)
		{
			syslog(LOG_DEBUG,"%s() ipv4 check_ip to string error\n",__FUNCTION__);
			return 0;
		}
		if(!is_valid_ipv4(addr_in->sin_addr))
		{
			syslog(LOG_DEBUG,"%s() ipv4 check_ip error -> %s\n",__FUNCTION__,ip_addr_char1);
			return 0;
		}
	}
	else if(check_ip.ss_family == AF_INET6)
	{
		struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&check_ip;
		if(inet_ntop(AF_INET6,&addr_in6->sin6_addr,ip_addr_char1,sizeof(ip_addr_char1)) == NULL)
		{
			syslog(LOG_DEBUG,"%s() ipv6 check_ip to string error\n",__FUNCTION__);
			return 0;
		}
		if(!is_valid_ipv6(addr_in6->sin6_addr))
		{
			syslog(LOG_DEBUG,"%s() ipv6 check_ip error -> %s\n",__FUNCTION__,ip_addr_char1);
			return 0;
		}
	}
	else
	{
		if(can_empty && check_ip.ss_family == 0)
		{
			return 1;
		}
		else
		{
			//syslog(LOG_DEBUG,"%s() check_ip unkown ss_family error -> %d\n",__FUNCTION__,check_ip.ss_family);
			return 0;
		}
	}
	return 1;
}

int is_valid_ipv4_string(char *ip_string)
{
	struct in_addr in_addr_tmp;

	if(inet_pton(AF_INET,ip_string,&in_addr_tmp) <= 0)
	{
		return 0;
	}
	else
	{
		return is_valid_ipv4(in_addr_tmp);
	}
}

int is_valid_ipv6_string(char *ip_string)
{
	struct in6_addr in6_addr_tmp;

	if(inet_pton(AF_INET6,ip_string,&in6_addr_tmp) <= 0)
	{
		return 0;
	}
	else
	{
		return is_valid_ipv6(in6_addr_tmp);
	}
}

int is_valid_ipv4_mask(uint8_t mask)
{
	if(mask > 0 && mask <= 32)
	{
		return 1;
	}
    return 0;
}

int is_valid_ipv6_mask(uint8_t mask)
{
	if(mask > 0 && mask <= 128)
	{
		return 1;
	}
    return 0;
}

int is_mac(const uint8_t *mac)
{
	if(mac)
	{
		int i;

		if(mac[0] == 0xff && mac[1] == 0xff && mac[2] == 0xff && mac[3] == 0xff && mac[4] == 0xff && mac[5] == 0xff)
			return 0;

		for(i=0;i<6;i++)
		{
			if(mac[i] != 0x00)return 1;
		}
	}

	return 0;
}

int is_mac_string(const char * mac)
{
	uint8_t i;
    char mac_temp[18];

	if(mac == NULL)
	{
		return 0;
	}
	if(strlen(mac) != 17)
		return 0;

    for(i=0;i<17;i++)
    {
        mac_temp[i] = tolower(mac[i]);
    }
    mac_temp[17] = '\0';
	if(strncmp(mac_temp,"00:00:00:00:00:00",17) == 0)return 0;
	if(strncmp(mac_temp,"ff:ff:ff:ff:ff:ff",17) == 0)return 0;

	for(i=0;i<17;i++)
	{
		if(i == 2||i == 5||i == 8||i == 11||i == 14)
		{
			if(mac_temp[i] != ':')return 0;
		}
		else
		{
			if((mac_temp[i] >= '0' && mac_temp[i] <= '9')||(mac_temp[i] >= 'a' && mac_temp[i] <= 'f'))
			{
				continue;
			}
			else
			{
				return 0;
			}
		}
	}

	return 1;
}

int inet46_pton(int family, const char *ip_strptr,struct sockaddr_storage *addr_in46)
{
	char printf_temp1[32];

	if((addr_in46 != NULL) && (ip_strptr != NULL) && (family == AF_INET || family == AF_INET6 || family == AF_INET46))
	{
		int ret = 0;
		if(strchr(ip_strptr,':') != NULL && (family == AF_INET6 || family == AF_INET46))
		{
			struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr_in46;
			if(inet_pton(AF_INET6,ip_strptr,&addr_in6->sin6_addr) <= 0)
			{
				strncpy(printf_temp1,ip_strptr,sizeof(printf_temp1));
				printf_temp1[sizeof(printf_temp1)-1] = '\0';
				syslog(LOG_DEBUG,"%s() ipv6 get unkown string %s\n",__FUNCTION__,printf_temp1);
				addr_in6->sin6_addr = in6addr_any;
				ret = -AF_INET6;
			}
			addr_in6->sin6_family = AF_INET6;
			ret = AF_INET6;
		}
		else if(strchr(ip_strptr,'.') != NULL && (family == AF_INET || family == AF_INET46))
		{
			struct sockaddr_in *addr_in = (struct sockaddr_in *)addr_in46;
			if(inet_pton(AF_INET,ip_strptr,&addr_in->sin_addr) <= 0)
			{
				strncpy(printf_temp1,ip_strptr,sizeof(printf_temp1));
				printf_temp1[sizeof(printf_temp1)-1] = '\0';
				syslog(LOG_DEBUG,"%s() ipv4 get unkown string %s\n",__FUNCTION__,printf_temp1);
				addr_in->sin_addr.s_addr = INADDR_ANY;
				ret = -AF_INET;
			}
			addr_in->sin_family = AF_INET;
			ret = AF_INET;
		}
		else if(strlen(ip_strptr))
		{//有不可识别的字符串
			strncpy(printf_temp1,ip_strptr,sizeof(printf_temp1));
			printf_temp1[sizeof(printf_temp1)-1] = '\0';
			syslog(LOG_DEBUG,"%s() ip_strptr get unkown string %s\n",__FUNCTION__,printf_temp1);
			addr_in46->ss_family = 0;
			ret = 0;
		}
		else
		{
			//syslog(LOG_DEBUG,"%s() ip_str get empty string\n",__FUNCTION__);
			addr_in46->ss_family = 0;
			ret = 1;
		}
		return ret;
	}
	return 0;
}

const char *inet46_ntop(int family,const struct sockaddr_storage *addr_in46, char *ip_strptr,size_t ip_strptr_size)
{
	if((addr_in46 != NULL) && (ip_strptr != NULL) && (ip_strptr_size > 0) && (family == AF_INET || family == AF_INET6 || family == AF_INET46))
	{
		if(addr_in46->ss_family == AF_INET && (family == AF_INET || family == AF_INET46))
		{
			struct sockaddr_in *addr_in = (struct sockaddr_in *)addr_in46;
			if(inet_ntop(AF_INET,&addr_in->sin_addr,ip_strptr,ip_strptr_size) == NULL)
			{
				syslog(LOG_ERR,"%s() ipv4 addr_in46 to string error -> %s\n",__FUNCTION__,strerror(errno));
				strcpy(ip_strptr,"");//出错设置为空
				return NULL;
			}
		}
		else if(addr_in46->ss_family == AF_INET6 && (family == AF_INET6 || family == AF_INET46))
		{
			struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)addr_in46;
			if(inet_ntop(AF_INET6,&addr_in6->sin6_addr,ip_strptr,ip_strptr_size) == NULL)
			{
				syslog(LOG_ERR,"%s() ipv6 addr_in46 to string error -> %s\n",__FUNCTION__,strerror(errno));
				strcpy(ip_strptr,"");//出错设置为空
				return NULL;
			}
		}
		else if(addr_in46->ss_family == 0)
		{
			strcpy(ip_strptr,"");//出错设置为空
			//数据为空返回原缓冲区
		}
		else
		{
			strcpy(ip_strptr,"");//出错设置为空
			return NULL;
		}
	}
	return ip_strptr;
}

uint8_t mac_atoe(const char *p,uint8_t *out)
{
	int i = 0;
	char *p_tmp = NULL;

	if(p == NULL || out == NULL)
		return 0;

	for (;;) {
		out[i++] = (char) strtoul(p, &p_tmp, 16);
		if (!*p_tmp || i == 6)
		{
			break;
		}
		else
		{
			p = p_tmp + 1;//p_tmp是:xx:xx:....的首地址,1是:部分的字符串
		}
	}

	return (i == 6);
}
#ifndef HAS_LIBMACRO
const char *mac_ntop(const void *src, char *dst, size_t size)
{
	const uint8_t *mac = (const uint8_t *)src;

	if (size < 18)
		return NULL;

	if (mac == NULL)
		return NULL;

	snprintf(dst,size,"%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0] & 0xff,
        mac[1] & 0xff,
        mac[2] & 0xff,
        mac[3] & 0xff,
        mac[4] & 0xff,
        mac[5] & 0xff);

	return dst;
}
#endif

int mask_ptoi(const char *ip)
{
	int i=0;
	int a[4]={0};
	int result = 0;

	if(ip == NULL)
		return 0;

	sscanf(ip, "%d.%d.%d.%d", &a[0], &a[1], &a[2], &a[3]);
	for(i=0; i<4; i++){	//this is dirty
		if(a[i] == 255){
			result += 8;
			continue;
		}
		if(a[i] == 254)
			result += 7;
		if(a[i] == 252)
			result += 6;
		if(a[i] == 248)
			result += 5;
		if(a[i] == 240)
			result += 4;
		if(a[i] == 224)
			result += 3;
		if(a[i] == 192)
			result += 2;
		if(a[i] == 128)
			result += 1;
		//if(a[i] == 0)
		//	result += 0;
		break;
	}
	return result;
}
#ifndef HAS_LIBMACRO
/**
 * hex_to_bin - convert a hex digit to its real value
 * @ch: ascii character represents hex digit
 *
 * hex_to_bin() converts one hex digit to its actual value or -1 in case of bad
 * input.
 */
static int hex_to_bin(char ch)
{
	if ((ch >= '0') && (ch <= '9'))
		return ch - '0';
	ch = tolower(ch);
	if ((ch >= 'a') && (ch <= 'f'))
		return ch - 'a' + 10;
	return -1;
}

uint8_t mac_pton(const char *s, uint8_t *mac)
{
#define ETH_ALEN 6
	int i;
	if(s == NULL || mac == NULL)
		return 0;
	/* XX:XX:XX:XX:XX:XX */
	if (strlen(s) < 3 * ETH_ALEN - 1)
		return 0;

	/* Don't dirty result unless string is valid MAC. */
	for (i = 0; i < ETH_ALEN; i++) {
		if (!isxdigit(s[i * 3]) || !isxdigit(s[i * 3 + 1]))
			return 0;
		if (i != ETH_ALEN - 1 && s[i * 3 + 2] != ':')
			return 0;
	}
	for (i = 0; i < ETH_ALEN; i++) {
		mac[i] = (hex_to_bin(s[i * 3]) << 4) | hex_to_bin(s[i * 3 + 1]);
	}
	return 1;
}
#endif
struct in_addr create_ipv4_mask(uint8_t prefixlen1)
{
	int				i;
	struct in_addr	n1;

	if(prefixlen1 > 32)prefixlen1 = 32;

	n1.s_addr = INADDR_ANY;

    for(i=0;i<prefixlen1;i++)
	{
		n1.s_addr |= 1<<i;
    }

	return n1;
}

struct in6_addr create_ipv6_mask(uint8_t prefixlen1)
{
	int				i;
	struct in6_addr	nk1;
    uint8_t 		*n1;
    int 			div;
	int				sub;

	if(prefixlen1 > 128)prefixlen1 = 128;

    memset(&nk1, 0, sizeof(nk1));

    div = prefixlen1/8;
    sub = prefixlen1%8;

    n1 = (uint8_t *)&(nk1.s6_addr);
	//生成掩码ffff:ffff:ffff:ffff:ffff:0000:0000:0000这中形式
    for (i=0; i<div; i++)
	{
		n1[i] = 0xff;
        //for (j=7; j>=0; j--)
		//{
        //    n1[i] |= 1<<j;
        //}
    }

    for (i=7; i>(7-sub); i--) {
		n1[div] |= 1<<i;
    }

    return nk1;
}

struct in_addr get_ipv4_subnet_prefix(struct in_addr ip1,uint8_t prefixlen1)
{
    int i;
	struct in_addr n1;
	n1.s_addr = INADDR_ANY;

    for (i=0; i < prefixlen1; i++)
	{
		n1.s_addr |= 1<<i;
    }
	ip1.s_addr &= n1.s_addr;

	return ip1;
}

struct in6_addr get_ipv6_subnet_prefix(struct in6_addr ip1,uint8_t prefixlen1)
{
    int i;
    struct in6_addr nk1;
    uint8_t *p1, *n1;
    int div , sub;

    memset(&nk1, 0, sizeof(nk1));

    div = prefixlen1/8;
    sub = prefixlen1%8;

    p1 = (uint8_t *)&(ip1.s6_addr);
    n1 = (uint8_t *)&(nk1.s6_addr);
	//生成掩码ffff:ffff:ffff:ffff:ffff:0000:0000:0000这中形式
    for (i=0; i<div; i++)
	{
		n1[i] = 0xff;
        //for (j=7; j>=0; j--)
		//{
        //    n1[i] |= 1<<j;
        //}
    }

    for (i=7; i>(7-sub); i--) {
		n1[div] |= 1<<i;
    }

	//掩码
    for (i=0; i<16; i++) {
		p1[i] &= n1[i];
    }
    return ip1;
}

int get_ipv4_subnet_cmp(struct in_addr ip1,struct in_addr ip2,uint8_t prefixlen1)
{
	struct in_addr ip_ret1 = get_ipv4_subnet_prefix(ip1,prefixlen1);
	struct in_addr ip_ret2 = get_ipv4_subnet_prefix(ip2,prefixlen1);

	if(ip_ret1.s_addr != ip_ret2.s_addr)
	{
		return -1;
	}

	return 0;
}

int get_ipv6_subnet_cmp(struct in6_addr ip1,struct in6_addr ip2,uint8_t prefixlen1)
{
    int i;
    struct in6_addr ip_ret1,ip_ret2;
    uint8_t *p1, *p2;

	ip_ret1 = get_ipv6_subnet_prefix(ip1,prefixlen1);

	ip_ret2 = get_ipv6_subnet_prefix(ip2,prefixlen1);

	p1 = ip_ret1.s6_addr;
	p2 = ip_ret2.s6_addr;

    for (i=0; i<16; i++)
	{
		if(p1[i] != p2[i])
		{
			return -1;
		}
    }
	return 0;
}

int get_ipv4_ip_if_subnet_cmp(struct in_addr ip1,const char *ifname,struct in_addr *cmp_ip,uint8_t *cmp_mask)
{
	int 			net_index;
	struct in_addr	if_ip[SYS_NET_IF_IP_MAX];
	uint8_t 		if_mask[SYS_NET_IF_IP_MAX];
	char			ip_addr_char1[64] = {0};
	if(ifname == NULL)
	{
		return -2;
	}

	if(is_valid_ipv4(ip1))
	{
		//从接口上读取可用的ip地址存储到if_ip和if_mask中
		for(net_index=0;net_index<SYS_NET_IF_IP_MAX;net_index++)
		{
			if_ip[net_index].s_addr = INADDR_ANY;
			if_mask[net_index] = 0;
			if(get_if_ip_string(ifname,AF_INET,net_index,ip_addr_char1,sizeof(ip_addr_char1),&if_mask[net_index]) != NULL)
			{
				if(inet_pton(AF_INET,ip_addr_char1,&if_ip[net_index]) <= 0)
				{
					if_ip[net_index].s_addr = INADDR_ANY;
					if_mask[net_index] = 0;
				}
			}
		}

		for(net_index=0;net_index<SYS_NET_IF_IP_MAX;net_index++)
		{
			if(is_valid_ipv4(if_ip[net_index]))
			{
				if(get_ipv4_subnet_cmp(if_ip[net_index],ip1,if_mask[net_index]) == 0)
				{
					if(cmp_ip)(*cmp_ip).s_addr = if_ip[net_index].s_addr;
					if(cmp_mask)*cmp_mask = if_mask[net_index];
					return 0;
				}
			}
		}
	}
	else
	{
		return -3;
	}

	return -1;
}

struct in6_addr get_ipv6_merge(struct in6_addr ip_prefix,struct in6_addr ip_tail,uint8_t prefixlen1)
{
	struct in6_addr ipv6_mask = create_ipv6_mask(prefixlen1);
    uint8_t *p_prefix, *p_tail, *p_mask;
    int i;

    p_prefix = (uint8_t *)&(ip_prefix.s6_addr);
    p_tail = (uint8_t *)&(ip_tail.s6_addr);
	p_mask = (uint8_t *)&(ipv6_mask.s6_addr);

	for(i=0; i<16; i++)
	{
		p_prefix[i] = (p_prefix[i]&p_mask[i]) | (p_tail[i]&(~p_mask[i]));
    }

	return ip_prefix;
}

int get_mac_form_ipv4_by_arp_cache(uint8_t *mac,struct in_addr ip_addr)
{//参考busybox->arp
	FILE *fp;
	int type, flags;
	int num;
	char ip[128];
	char hwa[128];
	char mask[128];
	char line[128];
	char dev[128];
	char ip_addr_char1[64] = {0};

	if(mac == NULL)return EINVAL;
	if(!is_valid_ipv4(ip_addr))return EINVAL;
	if(inet_ntop(AF_INET,&ip_addr,ip_addr_char1,sizeof(ip_addr_char1)) == NULL)
	{
		return EINVAL;
	}

	if((fp = fopen("/proc/net/arp","r")) == NULL)
	{
		return errno;
	}
	//去掉第一行
    if(fgets(line,sizeof(line),fp) <= 0)
    {

	}
    while(fgets(line,sizeof(line),fp) > 0)
    {
		mask[0] = '-'; mask[1] = '\0';
		dev[0] = '-'; dev[1] = '\0';
		//这里所有的缓冲器不会溢出,因为line的长度限制在128
		num = sscanf(line, "%s 0x%x 0x%x %s %s %s\n",ip, &type, &flags, hwa, mask, dev);
		if (num < 4)
		{//格式不对退出
			break;
		}

		if(strcmp(ip_addr_char1,ip) == 0)
		{//如果找到命中的IP,将字符形式的mac地址拷贝到mac缓冲区,准备返回
			uint8_t mac_tmp[6];
			if(mac_atoe(hwa,mac_tmp))
			{
				//这里有可能会溢出,需要保证mac缓冲区的大小大于6
				memcpy(mac,mac_tmp,6);
			}
			break;
		}
    }
	fclose(fp);

	return 0;
}

int get_mac_form_ipv6_by_ndp_cache(uint8_t *mac,struct in6_addr ip_addr)
{//参考busybox->arp
	FILE *fp;
	int num;
	char line[128];
	char ipv6[128];
	char dev_str[128];
	char dev[128];
	char lladdr_str[128];
	char hwa[128];
	char type[128];
	char ip_addr_char1[64] = {0};

	if(mac == NULL)return EINVAL;
	if(!is_valid_ipv6(ip_addr))return EINVAL;
	if(inet_ntop(AF_INET6,&ip_addr,ip_addr_char1,sizeof(ip_addr_char1)) == NULL)
	{
		return EINVAL;
	}

	if((fp = popen("/sbin/ip -6 neigh","r")) == NULL)
	{
		return errno;
	}

    while(fgets(line,sizeof(line),fp) > 0)
    {
		//这里所有的缓冲器不会溢出,因为line的长度限制在128
		num = sscanf(line, "%s %s %s %s %s %s\n",ipv6, dev_str, dev, lladdr_str, hwa, type);
		if (num < 6)
		{//格式不对退出
			break;
		}

		if(strcmp(ip_addr_char1,ipv6) == 0)
		{//如果找到命中的IP,将字符形式的mac地址拷贝到mac缓冲区,准备返回
			uint8_t mac_tmp[6];
			if(mac_atoe(hwa,mac_tmp))
			{
				//这里有可能会溢出,需要保证mac缓冲区的大小大于6
				memcpy(mac,mac_tmp,6);
			}
			break;
		}
    }
	pclose(fp);

	return 0;
}

int get_mac_form_ipv4_by_socket_cache(uint8_t *mac,char *ifname,struct in_addr ip_addr)
{
	int fd;
	struct arpreq arpreq;
	struct sockaddr_in *sin;
	int ret;

	if(mac == NULL)return EINVAL;
	if(ifname == NULL)return EINVAL;
	if(!is_valid_ipv4(ip_addr))return EINVAL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
	{
		return errno;
	}

	memset(&arpreq, 0, sizeof(struct arpreq));
	sin = (struct sockaddr_in *) &arpreq.arp_pa;
	sin->sin_family = AF_INET;
	memcpy(&sin->sin_addr, (char *)&ip_addr, sizeof(struct in_addr));
	strcpy(arpreq.arp_dev,ifname);

	ret = ioctl(fd, SIOCGARP, &arpreq);
	if (ret < 0)
	{
		return errno;
	}
	else
	{
		if(arpreq.arp_flags & ATF_COM)
		{
			memcpy(mac, (uint8_t *)arpreq.arp_ha.sa_data, 6);
			close(fd);// 关闭SOCKET
			return 0;
		}
		else
		{
			return -1;
		}
	}
	
	close(fd);// 关闭SOCKET
	return 0;
}

static int set_mac_ipv4_to_arptable(char *ifname,uint8_t *mac,struct in_addr ip_addr)
{
	int fd;
	struct arpreq arpreq;
	struct sockaddr_in *sin;
	int ret;

	if(mac == NULL)return EINVAL;
	if(!is_mac(mac))return EINVAL;
	if(ifname == NULL)return EINVAL;
	if(!is_valid_ipv4(ip_addr))return EINVAL;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if(fd < 0)
	{
		return errno;
	}

	memset(&arpreq, 0, sizeof(struct arpreq));
	sin = (struct sockaddr_in *)&arpreq.arp_pa;
	sin->sin_family = AF_INET;
	memcpy(&sin->sin_addr, (char *)&ip_addr, sizeof(struct in_addr));
	memcpy((uint8_t *)arpreq.arp_ha.sa_data,mac,6);
	arpreq.arp_flags = ATF_COM;
	strcpy(arpreq.arp_dev,ifname);

	ret = ioctl(fd, SIOCSARP, &arpreq);
	if (ret < 0)
	{
		close(fd);
		return errno;
	}

	close(fd);
	return 0;
}

int get_mac_form_ipv4_by_arp_req(uint8_t *dst_mac,char *ifname,struct in_addr src_ip,struct in_addr dst_ip)
{
	int fd;
	struct timeval tv;
	int ifindex = 0;
	struct ifreq ifr;
	uint8_t src_mac[6] = {0};
	//入口参数判断
	if(dst_mac == NULL)return EINVAL;
	if(ifname == NULL)return EINVAL;
	if(!is_valid_ipv4(src_ip))return EINVAL;
	if(!is_valid_ipv4(dst_ip))return EINVAL;
	// Default socket timeout 0.100 seconds
	tv.tv_sec = 0;
	tv.tv_usec = 100000;

	if((fd = socket(AF_PACKET, SOCK_DGRAM, htons(ETH_P_ARP))) < 0)
	{
		syslog(LOG_ERR,"%s()->socket(AF_PACKET) err -> %s",__PRETTY_FUNCTION__,strerror(errno));
		return errno;
	}
	//拷贝接口名
	strncpy(ifr.ifr_name, ifname, sizeof(ifr.ifr_name));
	ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
	//获取arp包发送时的接口索引
	if(ioctl(fd, SIOCGIFINDEX, &ifr) == -1)
	{
		syslog(LOG_ERR,"%s()->ioctl(SIOCGIFINDEX) err -> %s",__PRETTY_FUNCTION__,strerror(errno));
		close(fd);
		return errno;
	}
	ifindex = ifr.ifr_ifindex;
	//获取ndp包发送时的源地址mac地址
	memset(&ifr, 0, sizeof (ifr));
	snprintf(ifr.ifr_name, sizeof (ifr.ifr_name), "%s", ifname);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
	{
		syslog(LOG_ERR,"%s()->ioctl(SIOCGIFHWADDR,%s) err -> %s",__PRETTY_FUNCTION__,ifname,strerror(errno));
		close(fd);
		return errno;
	}
	memcpy(src_mac,(uint8_t *)ifr.ifr_addr.sa_data,sizeof(src_mac));
	//设置socket的超时时间防止阻塞
	if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		syslog(LOG_ERR,"%s()->setsockopt(SO_RCVTIMEO) err -> %s",__PRETTY_FUNCTION__,strerror(errno));
		close(fd);
		return errno;
	}
	//组包发送arp请求
	{
		const uint8_t ether_broadcast_addr[] = {0xff,0xff,0xff,0xff,0xff,0xff};
		struct sockaddr_ll addr = {0}, r_addr = {0};
		struct ether_arp req, *rep;
		struct iovec iov[1],r_iov[1];
		struct msghdr message;
		struct msghdr reply;
		char buffer[512];
		uint8_t	rev_count = 10;//100ms一次超时,最大接收10个不属于自己的包,然后超时退出

		memset(&message,0,sizeof(struct msghdr));
		memset(&reply,0,sizeof(struct msghdr));
		//构造目标地址
		addr.sll_family   = AF_PACKET;
		addr.sll_ifindex  = ifindex;
		addr.sll_halen    = ETHER_ADDR_LEN;
		addr.sll_protocol = htons(ETH_P_ARP);
		memcpy(addr.sll_addr, ether_broadcast_addr, ETHER_ADDR_LEN);
		//构造ARP请求包头
		req.arp_hrd = htons(ARPHRD_ETHER);
		req.arp_pro = htons(ETH_P_IP);
		req.arp_hln = ETHER_ADDR_LEN;
		req.arp_pln = sizeof(in_addr_t);
		req.arp_op	= htons(ARPOP_REQUEST);
		//构造ARP请求包源地址信息
		memcpy(req.arp_sha, src_mac, ETHER_ADDR_LEN);
		memcpy(&req.arp_spa, &src_ip.s_addr, sizeof(req.arp_spa));
		//构造ARP请求包目的地址信息
		memset(&req.arp_tha, 0, sizeof(req.arp_tha));
		memcpy(&req.arp_tpa, &dst_ip.s_addr, sizeof(req.arp_tpa));
		//构造sendmsg()函数用的信息
		iov[0].iov_base = &req;
		iov[0].iov_len = sizeof(req);
		message.msg_name = &addr;
		message.msg_namelen = sizeof(addr);
		message.msg_iov = iov;
		message.msg_iovlen = 1;
		message.msg_control = NULL;
		message.msg_controllen = 0;

		if(sendmsg(fd, &message, 0) == -1)
		{
			syslog(LOG_ERR,"%s()->sendmsg() err -> %s",__PRETTY_FUNCTION__,strerror(errno));
			close(fd);
			return errno;
		}
		//构造recvmsg()函数用的信息
	    r_iov[0].iov_base = buffer;
	    r_iov[0].iov_len  = sizeof(req);
	    reply.msg_name    = &r_addr;
	    reply.msg_namelen = sizeof(r_addr);
	    reply.msg_iov     = r_iov;
	    reply.msg_iovlen  = 1;
	    reply.msg_control = 0;
	    reply.msg_controllen = 0;
	    do { 
			ssize_t reply_len;
			if ((reply_len = recvmsg(fd, &reply, 0)) < 0)
			{
				syslog(LOG_ERR,"%s()->recvmsg() err -> %s",__PRETTY_FUNCTION__,strerror(errno));
				close(fd);
				return errno;
			}
			//查看是否是应答包和需要请求的mac地址
			rep = (struct ether_arp*)buffer;
			if (ntohs(rep->arp_op) == ARPOP_REPLY && (*(uint32_t*)rep->arp_spa == *(uint32_t*)req.arp_tpa))
			{
				memcpy(dst_mac, rep->arp_sha, 6);
				set_mac_ipv4_to_arptable(ifname,dst_mac,dst_ip);
	      		break;
			}
			else
			{
				syslog(LOG_DEBUG,"%s()->recvmsg() unkown info (rep->arp_op = %d,dst_ip = 0x%08x)",__PRETTY_FUNCTION__,ntohs(rep->arp_op),*(uint32_t*)rep->arp_spa);
			}
	    }
	    while(rev_count--);
	}
	close(fd);
	return 0;
}

static uint16_t ipv6_checksum(uint16_t *addr, int len)
{
	int count = len;
	register uint32_t sum = 0;
	uint16_t answer = 0;

	// Sum up 2-byte values until none or only one byte left.
	while (count > 1) {
		sum += *(addr++);
		count -= 2;
	}

	// Add left-over byte, if any.
	if (count > 0) {
		sum += *(uint8_t *) addr;
	}

	// Fold 32-bit sum into 16 bits; we lose information by doing this,
	// increasing the chances of a collision.
	// sum = (lower 16 bits) + (upper 16 bits shifted right 16 bits)
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Checksum is one's compliment of sum.
	answer = ~sum;

	return (answer);
}

int get_mac_form_ipv6_by_ndp_req(uint8_t *dst_mac,char *ifname,struct in6_addr src_ip,struct in6_addr dst_ip)
{
	int fd;
	//int	on;
	struct timeval tv;
	int ifindex = 0;
	struct ifreq ifr;
	uint8_t src_mac[6] = {0};
	//入口参数判断
	if(dst_mac == NULL)return EINVAL;
	if(ifname == NULL)return EINVAL;
	if(!is_valid_ipv6(src_ip))return EINVAL;
	if(!is_valid_ipv6(dst_ip))return EINVAL;
	// Default socket timeout 0.100 seconds
	tv.tv_sec = 0;
	tv.tv_usec = 100000;

	if((fd = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) < 0)
	{
		syslog(LOG_ERR,"%s()->socket(IPPROTO_ICMPV6) err -> %s",__PRETTY_FUNCTION__,strerror(errno));
		return errno;
	}
	//拷贝接口名
	memset(&ifr, 0, sizeof (ifr));
	snprintf(ifr.ifr_name, sizeof (ifr.ifr_name), "%s", ifname);
	//获取ndp包发送时的接口索引
	if(ioctl(fd, SIOCGIFINDEX, &ifr) < 0)
	{
		syslog(LOG_ERR,"%s()->ioctl(SIOCGIFINDEX) err -> %s",__PRETTY_FUNCTION__,strerror(errno));
		close(fd);
		return errno;
	}
	ifindex = ifr.ifr_ifindex;
	//获取ndp包发送时的源地址mac地址
	memset(&ifr, 0, sizeof (ifr));
	snprintf(ifr.ifr_name, sizeof (ifr.ifr_name), "%s", ifname);
	if(ioctl(fd, SIOCGIFHWADDR, &ifr) < 0)
	{
		syslog(LOG_ERR,"%s()->ioctl(SIOCGIFHWADDR,%s) err -> %s",__PRETTY_FUNCTION__,ifname,strerror(errno));
		close(fd);
		return errno;
	}
	memcpy(src_mac,(uint8_t *)ifr.ifr_addr.sa_data,sizeof(src_mac));
	//设置socket的超时时间防止阻塞
	if(setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
	{
		syslog(LOG_ERR,"%s()->setsockopt(SO_RCVTIMEO) err -> %s",__PRETTY_FUNCTION__,strerror(errno));
		close(fd);
		return errno;
	}
	//设置要接收到hop limit,附加数据区读取
	//on = 1;
	//if(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on)) < 0)
	//{
	//	syslog(LOG_ERR,"%s()->setsockopt(IPV6_RECVHOPLIMIT) err -> %s",__PRETTY_FUNCTION__,strerror(errno));
	//	close(fd);
	//	return errno;
	//}
	//设置要接收到目的IPv6地址和到达接口索引,附加数据区读取
	//on = 1;
	//if(setsockopt(fd, IPPROTO_IPV6, IPV6_RECVPKTINFO, &on, sizeof (on)) < 0) {
	//	syslog(LOG_ERR,"%s()->setsockopt(IPV6_RECVPKTINFO) err -> %s",__PRETTY_FUNCTION__,strerror(errno));
	//	close(fd);
	//	return errno;
	//}
	//绑定
	//if(setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof (ifr)) < 0) {
	//	syslog(LOG_ERR,"%s()->setsockopt(SO_BINDTODEVICE) err -> %s",__PRETTY_FUNCTION__,strerror(errno));
	//	close(fd);
	//	return errno;
	//}
	//组包发送ndp请求
	{
		int i;
		int psdhdrlen;
		uint8_t *psdhdr = NULL;
		uint8_t *send_buf = NULL;
		uint8_t *cmsg_buf = NULL;
		uint8_t options[1 + 1 + 6];// Option Type (1 byte) + Length (1 byte) + Length of MAC address (6 bytes)
		struct sockaddr_in6 src_in6, dst_in6, dstsnmc;
		struct nd_neighbor_solicit *ns;
		struct nd_neighbor_advert *na;
		struct msghdr message,reply;
		struct iovec iov[1],r_iov[1];
		struct cmsghdr *cmsghdr1, *cmsghdr2;
		struct sockaddr_ll r_addr = {0};
		uint8_t	rev_count = 10;//100ms一次超时,最大接收10个不属于自己的包,然后超时退出

		psdhdr = malloc(IP_MAXPACKET);
		if(psdhdr == NULL)
		{
			close(fd);
			return ENOMEM;
		}
		send_buf = malloc(IP_MAXPACKET);
		if(send_buf == NULL)
		{
			free(psdhdr);
			close(fd);
			return ENOMEM;
		}
		cmsg_buf = malloc(IP_MAXPACKET);//这里故意申请大一点的空间给接收时用
		if(cmsg_buf == NULL)
		{
			free(send_buf);
			free(psdhdr);
			close(fd);
			return ENOMEM;
		}
		memset(psdhdr,0,IP_MAXPACKET);
		memset(send_buf,0,IP_MAXPACKET);
		memset(cmsg_buf,0,CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct in6_pktinfo)));
		//源地址参数的处理
		memset(&src_in6, 0, sizeof(src_in6));
		src_in6.sin6_addr = src_ip;
		memcpy(psdhdr, src_in6.sin6_addr.s6_addr, 16 * sizeof(uint8_t));//将源地址复制一份到,校验计算缓冲区
		//目的地址参数的处理
		memset(&dst_in6, 0, sizeof(dst_in6));
		dst_in6.sin6_family = AF_INET6;
		dst_in6.sin6_addr = dst_ip;
		//将目标的IPv6单播地址转换为请求节点多播地址,Section 2.7.1 of RFC 4291.
		memset(&dstsnmc, 0, sizeof (struct sockaddr_in6));
		dstsnmc.sin6_addr.s6_addr[0]= 0xff;
		dstsnmc.sin6_addr.s6_addr[1]=0x02;
		for(i=2; i<11; i++) {
			dstsnmc.sin6_addr.s6_addr[i] = 0x00;
		}
		dstsnmc.sin6_addr.s6_addr[11]=0x01;
		dstsnmc.sin6_addr.s6_addr[12]=0xff;
		memcpy(psdhdr + 16, dstsnmc.sin6_addr.s6_addr, 16 * sizeof(uint8_t));//将目的地址复制一份到,校验计算缓冲区
		//如果不是站点本地或链接本地,则将套接字描述符绑定到源地址.
		if(!(psdhdr[0] == 0xfe))
		{
			syslog(LOG_ERR,"%s()psdhdr[0] = 0x%02x",__PRETTY_FUNCTION__,psdhdr[0]);
			syslog(LOG_ERR,"%s()psdhdr[1] = 0x%02x",__PRETTY_FUNCTION__,psdhdr[1]);
			syslog(LOG_ERR,"%s()psdhdr[2] = 0x%02x",__PRETTY_FUNCTION__,psdhdr[2]);
			syslog(LOG_ERR,"%s()psdhdr[3] = 0x%02x",__PRETTY_FUNCTION__,psdhdr[3]);
			if(bind(fd,(struct sockaddr *)&src_in6, sizeof(src_in6)) < 0) {
				syslog(LOG_ERR,"%s()->bind() err -> %s",__PRETTY_FUNCTION__,strerror(errno));
				free(cmsg_buf);
				free(send_buf);
				free(psdhdr);
				close(fd);
				return errno;
			}
		}
		//开始组建ndp的ns协议包头
		ns = (struct nd_neighbor_solicit *)send_buf;
		memset (ns, 0, sizeof (*ns));
		//填充ns请求结构的icmp6_hdr部分。
		ns->nd_ns_hdr.icmp6_type = ND_NEIGHBOR_SOLICIT;	// 135 (RFC 4861)
		ns->nd_ns_hdr.icmp6_code = 0;			   		// zero for neighbor solicitation (RFC 4861)
		ns->nd_ns_hdr.icmp6_cksum = htons(0);	   		// zero when calculating checksum
		ns->nd_ns_reserved = htonl(0);					// Reserved - must be set to zero (RFC 4861)
		ns->nd_ns_target = dst_ip;						// Target address (NOT MULTICAST) (as type in6_addr)
		//将选项附加到邻居请求结构的末尾
		options[0] = 1; 		  			// Option Type - "source link layer address" (Section 4.6 of RFC 4861)
		options[1] = sizeof(options) / 8;	// Option Length - units of 8 octets (RFC 4861)
		for (i=0; i<6; i++) {
			options[i+2] = src_mac[i];
		}
		memcpy(send_buf + sizeof (struct nd_neighbor_solicit), options, sizeof(options) * sizeof (uint8_t));
		//计算校验和时需要的数据长度(RFC 2460)
		//Length = source IP (16 bytes) + destination IP (16 bytes)
		//		 + upper layer packet length (4 bytes) + zero (3 bytes)
		//		 + next header (1 byte)
		psdhdrlen = 16 + 16 + 4 + 3 + 1 + sizeof (struct nd_neighbor_solicit) + sizeof(options);
		//构造sendmsg()函数用的信息
		memset (&message, 0, sizeof(message));
		message.msg_name = &dstsnmc;			//目的地址,这里填的是请求节点多播地址
		message.msg_namelen = sizeof(dstsnmc);
		memset (&iov, 0, sizeof (iov));
		iov[0].iov_base = (uint8_t *) send_buf;
		iov[0].iov_len = sizeof(struct nd_neighbor_solicit) + sizeof(options);
		message.msg_iov = iov;				  // scatter/gather array
		message.msg_iovlen = 1;				  // number of elements in scatter/gather array
		//这里需要额外设置hoplimit和接口索引,通过msg_control传递
		message.msg_control = cmsg_buf;
		message.msg_controllen = CMSG_SPACE(sizeof(int)) + CMSG_SPACE(sizeof(struct in6_pktinfo));
		{//设置hop limit为255根据(RFC 4861)neighbor solicitation协议的需求
			uint8_t hoplimit = 255u;
			cmsghdr1 = CMSG_FIRSTHDR(&message);
			cmsghdr1->cmsg_level = IPPROTO_IPV6;
			cmsghdr1->cmsg_type = IPV6_HOPLIMIT;  // We want to change hop limit
			cmsghdr1->cmsg_len = CMSG_LEN (sizeof (int));
			*(CMSG_DATA(cmsghdr1)) = hoplimit;
		}
		{//指定接口索引
			struct in6_pktinfo *pktinfo;
			cmsghdr2 = CMSG_NXTHDR (&message, cmsghdr1);
			cmsghdr2->cmsg_level = IPPROTO_IPV6;
			cmsghdr2->cmsg_type = IPV6_PKTINFO;  // We want to specify interface here
			cmsghdr2->cmsg_len = CMSG_LEN(sizeof(struct in6_pktinfo));
			pktinfo = (struct in6_pktinfo *)CMSG_DATA(cmsghdr2);
			pktinfo->ipi6_ifindex = ifindex;
		}
		//计算ICMPv6校验和(RFC 2460).
		//[ 0到15]由前面初始化源地址的时候设置
		//[16到31]由前面初始化目的地址的时候设置
		psdhdr[32] = 0;  // Length should not be greater than 65535 (i.e., 2 bytes)
		psdhdr[33] = 0;  // Length should not be greater than 65535 (i.e., 2 bytes)
		psdhdr[34] = (sizeof (struct nd_neighbor_solicit) + sizeof(options))  / 256;  // Upper layer packet length
		psdhdr[35] = (sizeof (struct nd_neighbor_solicit) + sizeof(options))  % 256;  // Upper layer packet length
		psdhdr[36] = 0;  // Must be zero
		psdhdr[37] = 0;  // Must be zero
		psdhdr[38] = 0;  // Must be zero
		psdhdr[39] = IPPROTO_ICMPV6;
		memcpy (psdhdr + 40, send_buf, (sizeof(struct nd_neighbor_solicit) + sizeof(options)) * sizeof (uint8_t));
		ns->nd_ns_hdr.icmp6_cksum = ipv6_checksum((uint16_t *)psdhdr, psdhdrlen);
		if(sendmsg(fd, &message, 0) == -1)
		{
			syslog(LOG_ERR,"%s()->sendmsg() err -> %s",__PRETTY_FUNCTION__,strerror(errno));
			free(cmsg_buf);
			free(send_buf);
			free(psdhdr);
			close(fd);
			return errno;
		}
		//构造recvmsg()函数用的信息
		memset (&reply, 0, sizeof(reply));
		memset(send_buf,0,IP_MAXPACKET);
		//memset(cmsg_buf,0,IP_MAXPACKET);
		r_iov[0].iov_base = send_buf;	//这里借用用过的发送缓冲区
		r_iov[0].iov_len  = IP_MAXPACKET;
		//reply.msg_name	  = NULL;
		//reply.msg_namelen = 0;
	    reply.msg_name    = &r_addr;
	    reply.msg_namelen = sizeof(r_addr);
		reply.msg_iov	  = r_iov;
		reply.msg_iovlen  = 1;
		reply.msg_control = NULL;//cmsg_buf;//这里借用用过的缓冲区
		reply.msg_controllen = 0;//IP_MAXPACKET * sizeof(uint8_t);
		do {
			ssize_t reply_len;
			if ((reply_len = recvmsg(fd, &reply, 0)) < 0)
			{
				syslog(LOG_ERR,"%s()->recvmsg() err -> %s",__PRETTY_FUNCTION__,strerror(errno));
				free(cmsg_buf);
				free(send_buf);
				free(psdhdr);
				close(fd);
				return errno;
			}
			//查看是否是应答包和需要请求的mac地址
			na = (struct nd_neighbor_advert *)send_buf;
			if(na->nd_na_type == ND_NEIGHBOR_ADVERT && memcmp(&na->nd_na_target,&dst_ip,sizeof(dst_ip)) == 0)
			{
				//(na->nd_na_flags_reserved & ND_NA_FLAG_ROUTER);
				memcpy(dst_mac,(send_buf + sizeof(struct nd_neighbor_advert) + 2),6);
	      		break;
			}
			else
			{
				char ip_addr_char1[64] = {0};
				if(inet_ntop(AF_INET6,&na->nd_na_target,ip_addr_char1,sizeof(ip_addr_char1)) == NULL)
				{
					strcpy(ip_addr_char1,"");//出错设置为空
				}
				syslog(LOG_DEBUG,"%s()->recvmsg() unkown info (na->nd_na_type = %d,dst_ip = %s)",__PRETTY_FUNCTION__,na->nd_na_type,ip_addr_char1);
			}
		}
		while(rev_count--);

		free(cmsg_buf);
		free(send_buf);
		free(psdhdr);
	}
	close(fd);
	return 0;
}

uint8_t is_file_exist(const char *path)
{
    return (access(path, F_OK|R_OK) == 0) ? 1 : 0;
}

int read_pid_from_file(const char *pidfilename)
{
	FILE *fp;
	int mypid;
	char pbuf[10];
	int status;

	if(pidfilename == NULL)
	{
		syslog(LOG_ERR,"%s() get point NULL\n",__FUNCTION__);
		return LIBEXC_INVALID_ARGUMENT;
	}

	if((fp = fopen(pidfilename,"r")) == NULL)
	{
		syslog(LOG_DEBUG, "%s() Can't read pid file %s error -> %s\n",__FUNCTION__,pidfilename,strerror(errno));
		return LIBEXC_OPEN_PID_FILE_ERR;//文件打开失败
	}
	status = fread(pbuf,sizeof(char),sizeof(pbuf) - 1,fp);
	fclose(fp);

	if(status > 0)
	{
		if(status < sizeof(pbuf))pbuf[status] = 0;
		mypid = atoi(pbuf);
		if (kill(mypid, 0) == 0)
			return mypid;
		if(errno == EPERM)
		{//kill()没有权限发送信号
			syslog(LOG_ERR, "%s() Send signal error -> %s\n",__FUNCTION__,strerror(errno));
			return LIBEXC_OPEN_KILL_OPERATION_NOT_ALLOWED;
		}
		return LIBEXC_KILL_NO_SUCH_PROCESS;//进程不存在
	}
	else
	{//未读到数据
		return LIBEXC_NO_DATA_READ;
	}
}

int pid_to_file(int mypid,char *path)
{//将PID值写入文件
	FILE *	fp;
	int 	ret;

	if(path)
	{
		if ((fp = fopen(path,"w")) == NULL)
		{
			syslog(LOG_ERR, "Can't create PID file %s error -> %s\n",path,strerror(errno));
			return errno;
		}
		ret = fprintf(fp,"%d\n",mypid);
		if(ret < 0)
		{
			syslog(LOG_ERR, "Can't write(fprintf) PID to file %s error -> %s\n",path,strerror(errno));
		}
		fclose(fp);

		syslog(LOG_DEBUG,"PID = %d write to file %s\n",mypid,path);
		return 0;
	}
	else
	{
		return EINVAL;
	}
}

/*****************************************************************************************
函数参数:	const char *domain	:输入的域名缓冲区
			char *serverip		:输出的IP缓冲区
函数功能:	从DNS获得域名的IP地址,目前只支持获取的第一个ip
函数返回:	0  成功
			-1 缓冲区指针为NULL
			-2 域名长度错误
			-3 ip地址类型非ipv4,现不支持IPV6
			-4 获得的ip地址长度非ipv4格式
			errno 系统错误代码
函数备注:	非多线程安全函数
			编译时需要以下头文件:
			#include <netdb.h>
			#include <sys/socket.h>
			#include <errno.h>
			#include <arpa/inet.h>
*****************************************************************************************/
int get_ip_byname(const char *domain, char *serverip)
{
	struct hostent * ret_addr;
	//入口参数检测
	if((domain == NULL) || (serverip == NULL))
	{
   		return -1;//缓冲区指针错误,程序无法检测,指针所指向空间的大小
	}
	if(strlen(domain) < 3 || strlen(domain) > 255)//有效的域名strlen("a.b")>=3,大于255的域名长度也不接受
	{
		printf("domain = %s too long 3~255\n",domain);
   		return -2;//域名长度错误
	}
	ret_addr = gethostbyname(domain);
	if(ret_addr == NULL)
	{
		return errno;//获取失败
	}
	//检测返回参数有效性
	if(ret_addr->h_addrtype != AF_INET)
	{
		printf("RC_get_serverip_from_domain get ip type error getiptype isnot ipv4\n");
   		return -3;//ip地址类型错误,非ipv4,现不支持IPV6
	}

	if(ret_addr->h_length != 4)
	{
		printf("RC_get_serverip_from_domain get ip len error getiplen = %d\n",ret_addr->h_length);
   		return -4;//ip地址长度错误
	}

	if(inet_ntop(ret_addr->h_addrtype,*(ret_addr->h_addr_list),serverip,16) == NULL)
	{
		return errno;
	}

	return 0;
}
