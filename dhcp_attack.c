/****************************
■ コマンドオプション
-i <Interface>        : 送信するインタフェース番号
-v                    : ログ冗長化
--loop <Loop>         : Discover送信回数
--interval <Interval> : Discover送信間隔 [us]
--client-count <Num>  : クライアント数 (MACアドレスの数)
--subscriber-count <Num> : 加入者数 (ctagのカウント)
--client-gw-addr <Addr> : 加入者ホームネットワークのGW
--dst-addr <Addr>       : 宛先(DHCPサーバ) IPアドレス
--src-addr <Addr>       : 送信元(DHCP Relay)IPアドレス
--dst-mac-addr <Mac>    : 宛先(DHCPサーバ) MACアドレス
--src-mac-addr <Mac>    : 送信元(DHCP Relay) MACアドレス
--sport                 : 送信元ポート番号
--dport                 : 宛先ポート番号

<指定例>
./dhcp_attack -i vnet1 --interval 10000 --loop 10000


■コンパイル
スレッドを使うのでオプション指定が必要です。
# gcc -lpthread -m64 -msse4.2 -O3 -I../dpdk/x86_64-default-linuxapp-gcc/include -L../dpdk/x86_64-default-linuxapp-gcc/lib -o dhcp_attack dhcp_attack.c

*****************************/
#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <errno.h>
#include <semaphore.h>
#include <pthread.h>
#include <search.h>
#include <getopt.h>

#include <net/if_packet.h>
#include <sys/socket.h>
#include <sys/time.h>

#if 0
#include <linux/in.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#else
#include <arpa/inet.h>
#endif

#include "rte_atomic.h"
#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_tailq.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>

#include <sched.h>

#include "dhcp.h"


#if RTE_MAX_LCORE == 1
#define MPLOCKED                        /**< No need to insert MP lock prefix. */
#else
#define MPLOCKED        "lock ; "       /**< Insert MP lock prefix. */
#endif

#if 0
typedef struct {
	volatile int32_t cnt; /**< An internal counter value. */
} rte_atomic32_t;
#endif

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

//#define BUFLEN 2000
#define BUFLEN 1500

#define DHCP_SNAME_LEN          64
#define DHCP_FILE_LEN           128

typedef struct {
	u_int8_t  op;           /* 0: Message opcode/type */
    u_int8_t  htype;        /* 1: Hardware addr type (net/if_types.h) */
    u_int8_t  hlen;         /* 2: Hardware addr length */
    u_int8_t  hops;         /* 3: Number of relay agent hops from client */
    u_int32_t xid;          /* 4: Transaction ID */
    u_int16_t secs;         /* 8: Seconds since client started looking */
    u_int16_t flags;        /* 10: Flag bits */
    struct in_addr ciaddr;  /* 12: Client IP address (if already in use) */
    struct in_addr yiaddr;  /* 16: Client IP address */
    struct in_addr siaddr;  /* 18: IP address of next server to talk to */
    struct in_addr giaddr;  /* 20: DHCP relay agent IP address */
    unsigned char chaddr[16];      /* 24: Client hardware address */
    char sname[DHCP_SNAME_LEN];    /* 40: Server name */
    char file[DHCP_FILE_LEN];      /* 104: Boot filename */
    unsigned char options[0];
} dhcp_pkt_t;

typedef struct {

	struct timeval prev_time;

	int status;
	volatile int start;
	rte_atomic32_t finished;
	struct timeval finished_time;

	struct {
		int verbose;
		int loop;
		int sleep;
		struct in_addr client_gw_addr;
		struct in_addr dst_addr;
		struct in_addr src_addr;
		u_int16_t sport;
		u_int16_t dport;
		unsigned int client_count;
		unsigned int subscriber_count;
		unsigned int thCnt;
		unsigned int corebase;
		char ifname[80];
		u_int8_t dst_mac_addr[6];
		u_int8_t src_mac_addr[6];
	} config;

} manager;

manager g_mgr;

#define E_THREAD_MAX    12  // 仮に 5とした
#define E_MAX_SUBSC_CNT   10000
typedef struct
{
	unsigned int  stag_base;   // 加入者番号
	unsigned int  ctag_base;   // 端末番号
	unsigned int  stag ;
	unsigned int  ctag ;

	int sock;

	struct {
		struct {
			/* 1秒毎にクリアする */
			rte_atomic32_t send_discover;
			rte_atomic32_t send_request;
			rte_atomic32_t received_ack;
		} per_sec;

		struct {
			/* 全体 */
			rte_atomic32_t send_discover;
			rte_atomic32_t send_request;
			rte_atomic32_t received_ack;
			rte_atomic32_t waiting_offer;
			rte_atomic32_t waiting_ack;
		} all;
	} counter;

	u_int8_t  msgBuf[BUFLEN] ;

	unsigned int  mapping[E_MAX_SUBSC_CNT][256]; // IP Address->xid Mapping
    unsigned char sndId[E_MAX_SUBSC_CNT] ;
    unsigned char rcvId[E_MAX_SUBSC_CNT] ;

} thData __attribute__((__aligned__(CACHE_LINE_SIZE)));

thData  g_thData[E_THREAD_MAX];

rte_atomic32_t nb_thread_starting;



#define DEBUG_PRINTF(...) if (unlikely(g_mgr.config.verbose)) { printf(__VA_ARGS__); }


#define log_printf(LEVEL, FMT, ARGs...) \
  printf(FMT, ##ARGs)

#define DbgError    printf

#if 0
/**
 * Initialize an atomic counter.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static inline void
rte_atomic32_init(rte_atomic32_t *v)
{
	v->cnt = 0;
}

/**
 * Atomically increment a counter by one.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static inline void
rte_atomic32_inc(rte_atomic32_t *v)
{
#ifndef RTE_FORCE_INTRINSICS
	asm volatile(
			MPLOCKED
			"incl %[cnt]"
			: [cnt] "=m" (v->cnt)   /* output */
			: "m" (v->cnt)          /* input */
			);
#else
	rte_atomic32_add(v, 1);
#endif
}

/**
 * Atomically decrement a counter by one.
 *
 * @param v
 *   A pointer to the atomic counter.
 */
static inline void
rte_atomic32_dec(rte_atomic32_t *v)
{
#ifndef RTE_FORCE_INTRINSICS
	asm volatile(
			MPLOCKED
			"decl %[cnt]"
			: [cnt] "=m" (v->cnt)   /* output */
			: "m" (v->cnt)          /* input */
			);
#else
	rte_atomic32_sub(v,1);
#endif
}
#endif

int set_priority(int policy)
{
    int    policy_max;
    int    ret = -1 ;

    if (0 <= (policy_max = sched_get_priority_max(policy)))
    {
        struct sched_param spp;

        spp.sched_priority = policy_max;
        ret = sched_setscheduler(0, policy, &spp);
        if (ret != 0){
            DbgError("sched_setscheduler() error : errno:%d\n",errno);
            DbgError("excecute at normal priority.\n");
        }
    }
    else
    {
        DbgError("sched_get_priority_max() error : errno:%d\n",errno);
        DbgError("excecute at normal priority.\n");
    }
    return ret;
}


char *
mac_address_str(u_int8_t *mac)
{
	static char mac_str[80];
	sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return mac_str;
}

char *
addr_str(struct in_addr addr)
{
	static char buf[80];
	u_int8_t *addr_ch;

	if (addr.s_addr == 0) {
		return "";
	}

	addr_ch = (u_int8_t *)&addr;

	sprintf(buf, "%u.%u.%u.%u", addr_ch[0], addr_ch[1], addr_ch[2], addr_ch[3]);

	return buf;
}

void
show_manager_config()
{
	printf("-- Config --\r\n");
	printf("-i/--interface : %s\r\n", g_mgr.config.ifname);
	printf("-v/--verbose : %s\r\n", g_mgr.config.verbose == 0 ? "false" : "true");
	printf("--loop : %d\r\n", g_mgr.config.loop);
	printf("--interval : %u [ns] \r\n", g_mgr.config.sleep);
	printf("--client-count : %u\r\n", g_mgr.config.client_count);
	printf("--subscriber-count : %u\r\n", g_mgr.config.subscriber_count);
	printf("--client-gw-addr : %s\r\n", addr_str(g_mgr.config.client_gw_addr));
	printf("--dst-addr : %s\r\n", addr_str(g_mgr.config.dst_addr));
	printf("--src-addr : %s\r\n", addr_str(g_mgr.config.src_addr));
	printf("--dst-mac-addr : %s\r\n", mac_address_str(g_mgr.config.dst_mac_addr));
	printf("--src-mac-addr : %s\r\n", mac_address_str(g_mgr.config.src_mac_addr));
	printf("--sport : %u\r\n", g_mgr.config.sport);
	printf("--dport : %u\r\n", g_mgr.config.dport);
	printf("--thread : %u\r\n", g_mgr.config.thCnt);
	printf("--core : %u\r\n", g_mgr.config.corebase);
}

int
bind_sock(void)
{
	int  sock;
	struct sockaddr_in sa;
	int ret;
	int yes = 1;
	int sockbuf=4194304 ;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (0>sock)
		return -1;

	if (setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, (const char *)&yes, sizeof(yes)) != 0) {
		close(sock);
		return -1;
	}
	
	if (setsockopt(sock, SOL_SOCKET, SO_RCVBUF, (const char *)&sockbuf, sizeof(sockbuf)) != 0) {
		close(sock);
		return -1;
	}
	
	if (setsockopt(sock, SOL_SOCKET, SO_SNDBUF, (const char *)&sockbuf, sizeof(sockbuf)) != 0) {
		close(sock);
		return -1;
	}
	
	sa.sin_family = AF_INET;
	sa.sin_port = 0;
	sa.sin_addr = g_mgr.config.src_addr;

	if (0 > bind(sock,(struct sockaddr *)&sa, sizeof(sa)))
	{
		close (sock);
		return -1;
	}

#ifdef SEND_CONNECT
	memset (&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(g_mgr.config.dport);
    sa.sin_addr   = g_mgr.config.dst_addr;

	if (0 > connect(sock,(struct sockaddr *)&sa, sizeof(sa)))
    {
        close (sock);
        return -1;
    }
#endif

	return(sock);
}


int
is_dhcp_relay_mode(void)
{
	if (g_mgr.config.client_gw_addr.s_addr != 0) {
		/* DHCP Relayの場合、DHCP Relay - Server間はUnicastなので  */
		/* src ipが指定されている場合は、DHCP Relay Modeと認識する */
		return 1;
	} else {
		return 0;
	}
}

int
send_packet(int sock, char *buf, int len)
{
	dhcp_pkt_t *dhcp;

	struct sockaddr_in sa;
	int ret;

	dhcp = (dhcp_pkt_t *)(buf);

#ifndef SEND_CONNECT  // connectしない方が速い...
	/* For some reason, SOCK_PACKET sockets can't be connected,
       so we have to do a sentdo every time. */
    memset (&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(g_mgr.config.dport);
    sa.sin_addr   = g_mgr.config.dst_addr;
    ret = sendto(sock, buf, len, MSG_DONTROUTE|MSG_DONTWAIT, (const struct sockaddr *)&sa, sizeof sa);
#else
    ret = send(sock, buf, len, 0);
#endif

    if (ret < 0) {
	    DbgError("#### send() NG(errno:%d)... sock:%d  xid:%x  yiaddr:%s\n",
	              errno, sock,
	             ((struct dhcp_packet*)buf)->xid, addr_str(((struct dhcp_packet*)buf)->yiaddr));
		return -1;
	}

    return ret;
}

char *
serch_option(u_int8_t *buf, int len, int dho)
{
	int offset = 0;

	while(offset < len) {
		int option_len;

		if (buf[offset] == dho) {
			return &buf[offset];
		}

		/* next byte is Length */
		offset += 1;

		option_len = buf[offset];
		offset += 1;

		/* skip option data */
		offset += option_len;
	}

	return NULL;
}

void
dhcp_show(dhcp_pkt_t *dhcp, u_int8_t type)
{
	char *type_str[] = {
		"Unknown",
		"Discover",
		"Offer",
		"Request",
		"Decline",
		"Ack",
		"Nak",
		"Release",
		"Inform",
		"LeaseQuery",
		"LeaseUnassigned",
		"LeaseUnknown",
		"LeaseActive",
	};

	if (type > 13) {
		type = 0;
	}

	DEBUG_PRINTF("dhcp %s (0x%x)\r\n", type_str[type], type);
	DEBUG_PRINTF("  xid = 0x%0x\r\n", ntohl(dhcp->xid));
	DEBUG_PRINTF("  ciaddr = %s\r\n", addr_str(dhcp->ciaddr));
	DEBUG_PRINTF("  yiaddr = %s\r\n", addr_str(dhcp->yiaddr));
	DEBUG_PRINTF("  siaddr = %s\r\n", addr_str(dhcp->siaddr));
	DEBUG_PRINTF("  giaddr = %s\r\n", addr_str(dhcp->giaddr));
}

u_int8_t dhcp_magic_cookie[] = { 0x63, 0x82, 0x53, 0x63 };

#define  Ddchp_RST_OK    0
#define  Ddchp_RST_NG   -1

static unsigned int  Nopt82DiscIdx ;
static unsigned int  Nopt50ReqIdx ;
static unsigned int  Nopt54ReqIdx ;
static unsigned int  Nopt82ReqIdx ;
static unsigned int  NmsgDcLen ;
static unsigned int  NmsgReqLen ;

static u_int8_t  NmsgDisc[BUFLEN] ;


static inline int option_size(const struct dhcp_option_type* p_opt)
{
    return p_opt->length + 2;
}

struct dhcp_option_type* next_option(struct dhcp_option_type* p_option)
{
    return (struct dhcp_option_type*) &p_option->content[p_option->length];
}

struct dhcp_option_type* copy_option(struct dhcp_option_type* p_dest, const struct dhcp_option_type* p_src)
{
    memcpy(p_dest, p_src, option_size(p_src));
    return next_option(p_dest);
}



int dhcpInitDiscover(struct dhcp_packet *a_packet)
{
    int  i ;
    int  ret;

    DEBUG_PRINTF("==>> %s() Start", __func__) ;

    a_packet->op    = BOOTREQUEST;
    a_packet->htype = HTYPE_ETHER;  // 1: Ethernet (10Mb)
    a_packet->hlen  = DHCP_MAX_HW_LEN ;  // 多分、chaddr(MAC)の長さ
    a_packet->hops  = 1 ;  // クライアントが0を設定し、要求がルータを経由する度に値がインクリメントされる。
    a_packet->xid   = 0 ;
    a_packet->secs  = 0 ;

    a_packet->flags = htons (BOOTP_BROADCAST);

    memset (&(a_packet->ciaddr), 0, sizeof(a_packet->ciaddr));
    memset (&(a_packet->yiaddr), 0, sizeof(a_packet->yiaddr));
    memset (&(a_packet->siaddr), 0, sizeof(a_packet->siaddr));
    memset (&(a_packet->giaddr), 0, sizeof(a_packet->giaddr));

    memset (&(a_packet->chaddr), 0, sizeof(a_packet->chaddr));
    memset (&(a_packet->sname ), 0, sizeof(a_packet->sname ));
    memset (&(a_packet->file  ), 0, sizeof(a_packet->file  ));

    a_packet->magic_cookie = DHCP_MAGIC_COOKIE ;
    ret = (uintptr_t)(&((struct dhcp_packet*)0)->options);

    memset (&(a_packet->options), 0, sizeof(a_packet->options));

    // ベタで書いてみるｗ (メッセージ長が簡単に算出できて楽ｗ)
    // メッセージ送信時に Option82の部分を決めうちで変更できる様にして
    // 高速化を図るｗｗｗ
    i=0 ;
    //  Option:53 DHCP Message Type
    a_packet->options[i++] = DHO_DHCP_MESSAGE_TYPE ;
    a_packet->options[i++] = 1 ;  // Length
    a_packet->options[i++] = DHCPDISCOVER ;

    //  Option:55 Parameter Request List
    //    1: Subnet Mask
    //    3: Router
    //    6: DNS
    a_packet->options[i++] = DHO_DHCP_PARAMETER_REQUEST_LIST ;
    a_packet->options[i++] = 3 ;  // Length
    a_packet->options[i++] = DHO_SUBNET_MASK ;
    a_packet->options[i++] = DHO_ROUTERS ;
    a_packet->options[i++] = DHO_DOMAIN_NAME_SERVERS ;

#if 0
    //  Option:61  Client ID 必要？ サーバ側で何か使っている？
    a_packet->options[i++] = DHO_DHCP_CLIENT_IDENTIFIER ;
    a_packet->options[i++] = 2 ;  // Length
    a_packet->options[i++] = 1 ;  // Type
    a_packet->options[i++] = 2 ;  // ClientID
#endif

    //  Option:82  Agent Information Option
    //    1: Agent Circuit ID
    a_packet->options[i++] = DHO_DHCP_AGENT_OPTIONS ;
    a_packet->options[i++] = 12 ;  // Length
    a_packet->options[i++] = RAI_CIRCUIT_ID ;
    a_packet->options[i++] = 10 ;  // Length
    Nopt82DiscIdx = i ;  // 本当は、1回だけ設定するべきだが、同じ動作なので同じ値が入るはず。簡易的に、これでやってみる
    i +=10 ;  // Tool側の管理データ 10Byteを送信時に設定

    //  Option:255 End
    a_packet->options[i++] = DHO_END ;

    DEBUG_PRINTF("<<== %s() End(ret:%d)", __func__, ret+i) ;
    return(ret+i);
}

//  0 <= subscId < 1,000,000(0x0F 42 40) or All F
//  seqId format
//    terminal No(0-199) : Upper 1 Byte
//    subscId            : Lower 3 Byte
int dhcpPerfDiscover(struct dhcp_packet *a_packet, unsigned int xid, unsigned int ctag,
                     unsigned int subscId, struct in_addr *a_ciaddr)
{
    DEBUG_PRINTF("==>> %s() Start", __func__) ;

    //a_packet->op    = BOOTREQUEST;
    //a_packet->htype = 1 ;  // 1: Ethernet (10Mb)
    //a_packet->hlen  = 6 ;  // 多分、chaddr(MAC)の長さ
    //a_packet->hops  = 1 ;  // クライアントが0を設定し、要求がルータを経由する度に値がインクリメントされる。
    //a_packet->secs  = 0 ;

    a_packet->xid   = xid;
    a_packet->chaddr[0] = 0x00 ;
    a_packet->chaddr[1] = 0x4C ;
    a_packet->chaddr[2] = ctag ;
    a_packet->chaddr[3] = subscId >> 16 ;
    a_packet->chaddr[4] = subscId >>  8 ;
    a_packet->chaddr[5] = subscId >>  0 ;

    //a_packet->flags = htons (BOOTP_BROADCAST);

    if (NULL == a_ciaddr)
        memset (&(a_packet->ciaddr), 0, sizeof(a_packet->ciaddr));
    else
        a_packet->ciaddr = *a_ciaddr;

    if (0xffffffff == subscId)
        memset (&(a_packet->giaddr), 0, sizeof(a_packet->giaddr));
    else
        a_packet->giaddr.s_addr = htonl((subscId & 0xFFFFFF00)+1) +1 ;

    //Option:82
#if 0
    a_packet->options[Nopt82DiscIdx  ] = '0';
    a_packet->options[Nopt82DiscIdx+1] = 'x';
    a_packet->options[Nopt82DiscIdx+2] = ((subscId >> 28)&0x0F) + '0' ;
    a_packet->options[Nopt82DiscIdx+3] = ((subscId >> 24)&0x0F) + '0' ;
    a_packet->options[Nopt82DiscIdx+4] = ((subscId >> 20)&0x0F) + '0' ;
    a_packet->options[Nopt82DiscIdx+5] = ((subscId >> 16)&0x0F) + '0' ;
    a_packet->options[Nopt82DiscIdx+6] = ((subscId >> 12)&0x0F) + '0' ;
    a_packet->options[Nopt82DiscIdx+7] = ((subscId >>  8)&0x0F) + '0' ;
    a_packet->options[Nopt82DiscIdx+8] = ((subscId >>  4)&0x0F) + '0' ;
    a_packet->options[Nopt82DiscIdx+9] = ((subscId >>  0)&0x0F) + '0' ;
#else
    snprintf(&a_packet->options[Nopt82DiscIdx],12, "%#010x%x", subscId,0xff);
#endif

    DEBUG_PRINTF("<<== %s() End(ret:%d)", __func__, Ddchp_RST_OK) ;
    return(Ddchp_RST_OK);
}


int dhcpInitRequest(struct dhcp_packet *a_packet)
{
    int  i ;
    int  ret;

    DEBUG_PRINTF("==>> %s() Start", __func__) ;

    a_packet->op    = BOOTREQUEST;
    a_packet->htype = HTYPE_ETHER;  // 1: Ethernet (10Mb)
    a_packet->hlen  = DHCP_MAX_HW_LEN ;  // 多分、chaddr(MAC)の長さ
    a_packet->hops  = 1 ;  // クライアントが0を設定し、要求がルータを経由する度に値がインクリメントされる。
    a_packet->xid   = 0 ;
    a_packet->secs  = 0 ;

    a_packet->flags = htons (BOOTP_BROADCAST);

    memset (&(a_packet->ciaddr), 0, sizeof(a_packet->ciaddr));
    memset (&(a_packet->yiaddr), 0, sizeof(a_packet->yiaddr));
    memset (&(a_packet->siaddr), 0, sizeof(a_packet->siaddr));
    memset (&(a_packet->giaddr), 0, sizeof(a_packet->giaddr));

    memset (&(a_packet->chaddr), 0, sizeof(a_packet->chaddr));
    memset (&(a_packet->sname ), 0, sizeof(a_packet->sname ));
    memset (&(a_packet->file  ), 0, sizeof(a_packet->file  ));

    a_packet->magic_cookie = DHCP_MAGIC_COOKIE ;
    ret = (uintptr_t)(&((struct dhcp_packet*)0)->options);

    memset (&(a_packet->options), 0, sizeof(a_packet->options));

    // ベタで書いてみるｗ (メッセージ長が簡単に算出できて楽ｗ)
    // メッセージ送信時に Option82の部分を決めうちで変更できる様にして
    // 高速化を図るｗｗｗ
    i=0 ;
    //  Option:53 DHCP Message Type (REQUEST)
    a_packet->options[i++] = DHO_DHCP_MESSAGE_TYPE ;
    a_packet->options[i++] = 1 ;  // Length
    a_packet->options[i++] = DHCPREQUEST ;

    //  Option:50  Requested IP Address
    a_packet->options[i++] = DHO_DHCP_REQUESTED_ADDRESS ;
    a_packet->options[i++] = 4 ;  // Length
    Nopt50ReqIdx = i ;
    i +=4 ;

    //  Option:54  Server Identifier
    Nopt54ReqIdx = i ;
    a_packet->options[i++] = DHO_DHCP_SERVER_IDENTIFIER ;
    a_packet->options[i++] = 4 ;  // Length
    //Nopt50ReqIdx = i ;
    i +=4 ;

    //  Option:55 Parameter Request List
    //    1: Subnet Mask
    //    3: Router
    //    6: DNS
    a_packet->options[i++] = DHO_DHCP_PARAMETER_REQUEST_LIST ;
    a_packet->options[i++] = 3 ;  // Length
    a_packet->options[i++] = DHO_SUBNET_MASK ;
    a_packet->options[i++] = DHO_ROUTERS ;
    a_packet->options[i++] = DHO_DOMAIN_NAME_SERVERS ;

#if 0
    //  Option:61  Client ID 必要？ サーバ側で何か使っている？
    a_packet->options[i++] = DHO_DHCP_CLIENT_IDENTIFIER ;
    a_packet->options[i++] = 2 ;  // Length
    a_packet->options[i++] = 1 ;  // Type
    a_packet->options[i++] = 2 ;  // ClientID
#endif

    //  Option:82  Agent Information Option
    //    1: Agent Circuit ID
    a_packet->options[i++] = DHO_DHCP_AGENT_OPTIONS ;
    a_packet->options[i++] = 12 ;  // Length
    a_packet->options[i++] = RAI_CIRCUIT_ID ;
    a_packet->options[i++] = 10 ;  // Length
    Nopt82ReqIdx = i ;  // 本当は、1回だけ設定するべきだが、同じ動作なので同じ値が入るはず。簡易的に、これでやってみる
    i +=10 ;  // Tool側の管理データ 10Byteを送信時に設定

    //  Option:255 End
    a_packet->options[i++] = DHO_END ;

    DEBUG_PRINTF("<<== %s() End(ret:%d)", __func__, ret+i) ;
    return(ret+i);
}

//  0 <= subscId < 1,000,000(0x0F 42 40) or All F
//  seqId format
//    terminal No(0-199) : Upper 1 Byte
//    subscId            : Lower 3 Byte
int dhcpPerfRequest(struct dhcp_packet *a_packet, unsigned int xid, unsigned char *a_chaddr,
                     unsigned int subscId, struct in_addr *a_ciaddr,
                     struct in_addr *a_reqIP, struct dhcp_option_type *a_srvId)
{
    DEBUG_PRINTF("==>> %s() Start", __func__) ;

    a_packet->xid   = xid;
    memcpy(a_packet->chaddr, a_chaddr, sizeof(a_packet->chaddr));

    //a_packet->flags = htons (BOOTP_BROADCAST);

    if (NULL == a_ciaddr)
        memset (&(a_packet->ciaddr), 0, sizeof(a_packet->ciaddr));
    else
        a_packet->ciaddr = *a_ciaddr;

    if (0xffffffff == subscId)
        memset (&(a_packet->giaddr), 0, sizeof(a_packet->giaddr));
    else
        a_packet->giaddr.s_addr = htonl((subscId & 0xFFFFFF00)+1) +1 ;

    //Option:50
    // Inパラの内容チェックをしていないが、信用して動く
    //copy_option((struct dhcp_option_type*)&a_packet->options[Nopt50ReqIdx], a_reqIP);
    a_packet->options[Nopt50ReqIdx  ] =  a_reqIP->s_addr >>  0 ;
    a_packet->options[Nopt50ReqIdx+1] =  a_reqIP->s_addr >>  8 ;
    a_packet->options[Nopt50ReqIdx+2] =  a_reqIP->s_addr >> 16 ;
    a_packet->options[Nopt50ReqIdx+3] =  a_reqIP->s_addr >> 24 ;

    //Option:54
    // Inパラの内容チェックをしていないが、信用して動く
    copy_option((struct dhcp_option_type*)&a_packet->options[Nopt54ReqIdx], a_srvId);

    //Option:82
#if 0
    a_packet->options[Nopt82ReqIdx  ] = '0';
    a_packet->options[Nopt82ReqIdx+1] = 'x';
    a_packet->options[Nopt82ReqIdx+2] = ((subscId >> 28)&0x0F) + '0' ;
    a_packet->options[Nopt82ReqIdx+3] = ((subscId >> 24)&0x0F) + '0' ;
    a_packet->options[Nopt82ReqIdx+4] = ((subscId >> 20)&0x0F) + '0' ;
    a_packet->options[Nopt82ReqIdx+5] = ((subscId >> 16)&0x0F) + '0' ;
    a_packet->options[Nopt82ReqIdx+6] = ((subscId >> 12)&0x0F) + '0' ;
    a_packet->options[Nopt82ReqIdx+7] = ((subscId >>  8)&0x0F) + '0' ;
    a_packet->options[Nopt82ReqIdx+8] = ((subscId >>  4)&0x0F) + '0' ;
    a_packet->options[Nopt82ReqIdx+9] = ((subscId >>  0)&0x0F) + '0' ;
#else
    snprintf(&a_packet->options[Nopt82ReqIdx],12, "%#010x%x", subscId,0xff);
#endif

    DEBUG_PRINTF("<<== %s() End(ret:%d)", __func__, Ddchp_RST_OK) ;
    return(Ddchp_RST_OK);
}




volatile  static unsigned int  Counter = 0;

void
signal_handler(int signum)
{
	long int intverval;
	struct timeval now;
	struct timeval now2;
	unsigned long  per_discover=0, per_request=0, per_ack=0;
	unsigned long  all_discover=0, all_request=0, all_ack=0, wait_offer=0, wait_ack=0;
	unsigned int i, j, k ;

	gettimeofday(&now, NULL);
	for (i=0; i<g_mgr.config.thCnt*2; i++)
	{
		per_discover += g_thData[i].counter.per_sec.send_discover.cnt; rte_atomic32_init(&g_thData[i].counter.per_sec.send_discover);
		per_request  += g_thData[i].counter.per_sec.send_request.cnt ; rte_atomic32_init(&g_thData[i].counter.per_sec.send_request );
		per_ack      += g_thData[i].counter.per_sec.received_ack.cnt ; rte_atomic32_init(&g_thData[i].counter.per_sec.received_ack );
		all_discover += g_thData[i].counter.all.send_discover.cnt;
		all_request  += g_thData[i].counter.all.send_request.cnt ;
		all_ack      += g_thData[i].counter.all.received_ack.cnt ;
		wait_offer   += g_thData[i].counter.all.waiting_offer.cnt;
		wait_ack     += g_thData[i].counter.all.waiting_ack.cnt  ;
	}

	intverval = (now.tv_sec - g_mgr.prev_time.tv_sec) * 1000 + (now.tv_usec - g_mgr.prev_time.tv_usec) / 1000;

	printf("Interval %ld : Send Discover %lu/%lu, Request %lu/%lu, Received Ack %lu/%lu, Waiting Offer %lu, Ack %lu\n",
	       intverval,
	       per_discover, all_discover,
	       per_request, all_request,
	       per_ack, all_ack,
	       wait_offer, wait_ack);

	g_mgr.prev_time = now;

	/* 終了判定 */
	if (!g_mgr.finished.cnt && now.tv_sec - g_mgr.finished_time.tv_sec > 5) {

	    /* 全てのDiscoverを送信して5秒後に終了 */
		unsigned int  errCnt = 0 ;

		for (i=0; i<g_mgr.config.thCnt; i++)
		{
		    printf("id-%d : Send Discover %lu, Request %lu, Received Ack %lu, Waiting Offer %lu, Ack %lu\n",
		       i,
		       g_thData[i].counter.all.send_discover.cnt+ g_thData[g_mgr.config.thCnt+i].counter.all.send_discover.cnt,
		       g_thData[i].counter.all.send_request.cnt + g_thData[g_mgr.config.thCnt+i].counter.all.send_request.cnt,
		       g_thData[i].counter.all.received_ack.cnt + g_thData[g_mgr.config.thCnt+i].counter.all.received_ack.cnt,
		       g_thData[i].counter.all.waiting_offer.cnt+ g_thData[g_mgr.config.thCnt+i].counter.all.waiting_offer.cnt, 
		       g_thData[i].counter.all.waiting_ack.cnt  + g_thData[g_mgr.config.thCnt+i].counter.all.waiting_ack.cnt);

		    for (j=0; j < E_MAX_SUBSC_CNT; ++j)
		        for (k=0; k<256 & errCnt<50; ++k)
		        {
		            unsigned int data ;
		            data = g_thData[i].mapping[j][k] ;

		            if (data>>24 != ((data>>16)&0x000000ff))
		                printf("#### [%03d] Unmatch subscid:%#x ipaddr:x.x.x.%d data:%#x\n", ++errCnt, g_thData[i].stag_base+i, k, data);
		        }
		}

		exit(0);
	}
}

void
start_timer_handler(void)
{
	struct sigaction action;
	struct itimerval timer;

	memset(&action, 0, sizeof(action));

	/* set signal handler */
	action.sa_handler = signal_handler;
	action.sa_flags = SA_RESTART;
	sigemptyset(&action.sa_mask);
	if(sigaction(SIGALRM, &action, NULL) < 0){
		perror("sigaction error");
		exit(1);
	}

	gettimeofday(&g_mgr.prev_time, NULL);

	/* set intarval timer (1sec) */
	timer.it_value.tv_sec = 1;
	timer.it_value.tv_usec = 0;
	timer.it_interval.tv_sec = 1;
	timer.it_interval.tv_usec = 0;
	if(setitimer(ITIMER_REAL, &timer, NULL) < 0){
		perror("setitimer error");
		exit(1);
	}
}


static inline void
recv_dhcp(thData  *a_thData, int flags)
{
	int len, t_len=0;
	dhcp_pkt_t *dhcp;
	int dhcp_option_len;
	u_int8_t *message_type;
	u_int8_t buf[BUFLEN];
	int  t_ret ;
	int  i ;
	unsigned int *a_mapping ;

	do
	{
		len = recvfrom(a_thData->sock, buf, sizeof(buf), flags, NULL, NULL);

		if (0 >= len)
		{
			break;
		}
		
		if (t_len != len)
		{
            if (0 == t_len)
            {
                t_len = len ;
            }
            else
            {
			    DbgError("#### Length Unmatch... len:%u t_len:%u\n", len, t_len);
			}
		}

		dhcp = (dhcp_pkt_t *)buf;

		//dhcp_option_len = ntohs(udp->ulen) - sizeof(udp_hdr_t) - sizeof(dhcp_pkt_t) - sizeof(dhcp_magic_cookie);
		dhcp_option_len = len - sizeof(*dhcp) ;
		message_type = serch_option(&dhcp->options[4], dhcp_option_len, 53);
		if (message_type == NULL) {
			/* メッセージタイプがない */
			DbgError("#### No MessageType Message Recv. xid=%#x\n", dhcp->xid);
			continue;
		}

		//dhcp_show(dhcp, message_type[2]);
		a_mapping = &a_thData->mapping[(dhcp->xid&0x00ffffff)-a_thData->stag_base][dhcp->yiaddr.s_addr>>24] ;

		if (message_type[2] == 2) {
			/* Recieved Offer */
			u_int8_t *server_id = NULL;
			u_int8_t *a_agentCid = NULL;

			server_id = serch_option(&dhcp->options[4], dhcp_option_len, 54);

			dhcpPerfRequest((struct dhcp_packet *)a_thData->msgBuf, dhcp->xid, dhcp->chaddr, dhcp->xid&0x00FFFFFF, NULL, &dhcp->yiaddr, (struct dhcp_option_type *)server_id);

	        send_packet(a_thData->sock, a_thData->msgBuf, NmsgReqLen);

			/* 統計★要排他★ */
			rte_atomic32_inc(&a_thData->counter.per_sec.send_request);
			rte_atomic32_inc(&a_thData->counter.all.send_request);
			rte_atomic32_dec(&a_thData->counter.all.waiting_offer);
			rte_atomic32_inc(&a_thData->counter.all.waiting_ack);

			if ((*a_mapping & 0x000000FF)^dhcp->chaddr[2])
            {
                if (0 != ((*a_mapping)&0x0000FFFF))
                {
                    DbgError("#### DHCP_Offer Same IpAddr Assigned. xid=%#010x ctag=%#x yiaddr=%s cnt=%#010x\n",
                             dhcp->xid, dhcp->chaddr[2], addr_str(dhcp->yiaddr), *a_mapping);
                }
            }

            *a_mapping = (*a_mapping+0x00010000)&0x00FF0000 |
                         (*a_mapping           )&0xFF00FFFF ;
		}
		else if (message_type[2] == 5) {
			/* Received Ack 要排他★ */
			//client_delete(client, &a_thData->client_db, &a_thData->sem);
			//free(client);
			rte_atomic32_inc(&a_thData->counter.per_sec.received_ack);
			rte_atomic32_inc(&a_thData->counter.all.received_ack);
			rte_atomic32_dec(&a_thData->counter.all.waiting_ack);

			if ((unsigned char)(a_thData->rcvId[(dhcp->xid&0x00ffffff)-a_thData->stag_base]+1) != (unsigned char)(dhcp->xid>>24))
                DbgError("#### DHCP_ACK Unmatch SeqId. xid=%#010x expected Id=%#04x\n",
                         dhcp->xid, a_thData->rcvId[(dhcp->xid&0x00ffffff)-a_thData->stag_base]+1);

			a_thData->rcvId[(dhcp->xid&0x00ffffff)-a_thData->stag_base] = (dhcp->xid>>24);

			if ((*a_mapping & 0x000000FF)^dhcp->chaddr[2])
			{
			    if (0 != ((*a_mapping)&0x0000FFFF))
			    {
		            DbgError("#### DHCP_ACK Same IpAddr Assigned. xid=%#010x ctag=%#x yiaddr=%s cnt=%#010x\n",
		                     dhcp->xid, dhcp->chaddr[2], addr_str(dhcp->yiaddr), *a_mapping);
			    }

			    *a_mapping = dhcp->chaddr[2];
			}

			*a_mapping = (*a_mapping+0x01000000)&0xFF000000 |
			             (*a_mapping           )&0x00FFFFFF ;
		}
		else {
			DbgError("#### MessageType Error. xid=%#x type:%d \n", dhcp->xid, message_type[2]);
			continue;
		}
	} while(0);
}

#ifdef DPDK_USE
int 
#else
void *
#endif
start_client(void* arg)
{
	int  i, j, loop=g_mgr.config.loop ;
	volatile unsigned int tmp = 100000;
	struct timespec  reqTime = {0, 0};
	
	sigset_t ss;
	int t_ret, signo;
	
	sigemptyset(&ss);
	t_ret = sigaddset(&ss, SIGALRM);
    if (t_ret != 0) 
        return 1;
    t_ret = sigprocmask(SIG_BLOCK, &ss, NULL);
    if (t_ret != 0) 
        return 1;
	
	thData  *a_thData = (thData*)arg;
	
	while(!g_mgr.start)
		usleep(10);


	while(1)
	{
	    for (i=0; i<g_mgr.config.thCnt; i++)
	    {
#if 0
            if (g_mgr.config.sleep+(tmp/10000) != 0)
            {
                reqTime.tv_nsec = g_mgr.config.sleep+tmp ;

                nanosleep(&reqTime, NULL);
                //usleep(g_mgr.config.sleep+(tmp/10000));
                if (0 < tmp) --tmp;
            }
#else
            for (j=0; j<g_mgr.config.sleep; ++j)
                tmp += 1 ;
#endif

            dhcpPerfDiscover((struct dhcp_packet *)NmsgDisc,
                             ((++a_thData[i].sndId[a_thData[i].stag-a_thData[i].stag_base])<<24)+a_thData[i].stag,
                             a_thData[i].ctag, a_thData[i].stag, NULL);

            send_packet(a_thData[i].sock, NmsgDisc, NmsgDcLen);

            /* 統計 */
            rte_atomic32_inc(&a_thData[i].counter.per_sec.send_discover);
            rte_atomic32_inc(&a_thData[i].counter.all.send_discover);
            rte_atomic32_inc(&a_thData[i].counter.all.waiting_offer);

            if (0 >= --loop)
                goto END ;

            /* ctagを加算 */
            a_thData[i].stag++;
            if (a_thData[i].stag >= a_thData[i].stag_base+g_mgr.config.subscriber_count/g_mgr.config.thCnt) {
                a_thData[i].stag = a_thData[i].stag_base;
                ++a_thData[i].ctag;
                if (a_thData[i].ctag_base+g_mgr.config.client_count <= a_thData[i].ctag)
                    a_thData[i].ctag = a_thData[i].ctag_base;
            }
	    }
	}
END:
	printf("Finished\r\n");

	gettimeofday(&g_mgr.finished_time, NULL);
	rte_atomic32_dec(&g_mgr.finished);

#if 0
	while (a_thData->counter.all.waiting_offer.cnt && a_thData->counter.all.waiting_ack.cnt)
	{
		recv_dhcp(a_thData, 0);
	}
#endif
	return 0;
}

#ifdef DPDK_USE
int 
#else
void *
#endif
recv_thread(void *arg)
{
	int  t_ret ;
	thData  *a_thData = (thData*)arg;
	
	
	sigset_t ss;
	int  signo;
	
	sigemptyset(&ss);
	t_ret = sigaddset(&ss, SIGALRM);
    if (t_ret != 0) 
        return 1;
    t_ret = sigprocmask(SIG_BLOCK, &ss, NULL);
    if (t_ret != 0) 
        return 1;
	
#ifdef DPDK_USE
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	printf("recv_thread from core %u\n", lcore_id);
#endif
	
	rte_atomic32_dec(&nb_thread_starting);
	
	while(g_mgr.status)
	{
		recv_dhcp(a_thData, 0);
	}
	return 0;
}

#define  E_CPU_BASE    12

int
start(void)
{
	int i ;
#ifdef DPDK_USE
	unsigned lcore_id = -1 ;
#else
	pthread_t thread;
    cpu_set_t cpuset;
#endif
    g_mgr.status = 1;

	rte_atomic32_set(&nb_thread_starting, 1);
	
    printf("Rcv Thread working core(s): ");
    
	for (i=0; i<g_mgr.config.thCnt; i++)
	{
		memset(&g_thData[i], 0, sizeof(g_thData[i]));

		g_thData[i].stag = g_thData[i].stag_base = 200 + g_mgr.config.subscriber_count*i;
		g_thData[i].ctag = g_thData[i].ctag_base = 0 ;

		g_thData[i].sock = bind_sock() ;  // Thread毎に別々の Socketの方が速い...
		if (0>g_thData[i].sock)
		{
			printf("#### socket err...####\n");
			exit(0);
		}
		
		NmsgReqLen = dhcpInitRequest((struct dhcp_packet *)g_thData[i].msgBuf);

		rte_atomic32_inc(&nb_thread_starting);
		
#ifdef DPDK_USE
		for (lcore_id=rte_get_next_lcore(lcore_id,1,0);
		     lcore_id<RTE_MAX_LCORE ;
		     lcore_id=rte_get_next_lcore(lcore_id,1,0))
		{
			rte_eal_remote_launch(recv_thread, (void*)&g_thData[i], lcore_id);
		    break ;
		}
#else
		if (0 != pthread_create(&thread, NULL, recv_thread, &g_thData[i]))
		{
			printf("#### recv_thread() create err...####\n");
			exit(0);
		}
        CPU_ZERO( &cpuset );
        CPU_SET ( g_mgr.config.corebase+i, &cpuset );
        if (0 != pthread_setaffinity_np(thread, sizeof( cpuset ), &cpuset))
        {
            printf("pthread_setaffinity_np failed\n");
            return -1;
        }
        else
        {
            printf("%d ", g_mgr.config.corebase+i);
        }
#endif
	}

	rte_atomic32_dec(&nb_thread_starting);
	printf("thread:%d \n", i);
	//waiting all threads are reading
	while(nb_thread_starting.cnt != 0){
		usleep(1);
	}
	
    printf("Send Thread working core(s): ");
    
    NmsgDcLen = dhcpInitDiscover((struct dhcp_packet *)NmsgDisc);

    if (0 != pthread_create(&thread, NULL, start_client, g_thData))
    {
        printf("#### start_client() create err...####\n");
        exit(0);
    }
    CPU_ZERO( &cpuset );
    CPU_SET ( g_mgr.config.corebase+i, &cpuset );
    if (0 != pthread_setaffinity_np(thread, sizeof( cpuset ), &cpuset))
    {
        printf("pthread_setaffinity_np failed\n");
        return -1;
    }
    else
    {
        printf("%d ", g_mgr.config.corebase+i);
    }
    rte_atomic32_inc(&g_mgr.finished);
	
    printf("thread:%d \n", i);
	start_timer_handler();
	g_mgr.start = 1;

#ifdef DPDK_USE
	rte_eal_mp_wait_lcore();
#else
    do {
        sleep(1) ;
    } while (g_mgr.status);
#endif

    return 0;
}

int
main(int argc, char *argv[])
{
	int opt, option_index;

	struct option long_options[] = {
		{ "loop", required_argument, NULL, 0 }, // 0
		{ "interval", required_argument, NULL, 0 }, // 1
		{ "client-count", required_argument, NULL, 0 }, // 2
		{ "client-gw-addr", required_argument, NULL, 0 }, // 3
		{ "dst-addr", required_argument, NULL, 0 }, // 4
		{ "src-addr", required_argument, NULL, 0 }, // 5
		{ "dst-mac-addr", required_argument, NULL, 0 },  // 6
		{ "src-mac-addr", required_argument, NULL, 0 },  // 7
		{ "sport", required_argument, NULL, 0 }, // 8
		{ "dport", required_argument, NULL, 0 }, // 9
		{ "subscriber-count", required_argument, NULL, 0}, // 10
		{ "thread", required_argument, NULL, 0},  // 11
		{ "core", required_argument, NULL, 0 }, // 12
		{ "interface", required_argument, NULL, 'i' },
		{ "verbose", no_argument, NULL, 'v' },
		{0, 0, 0, 0},
	};

	/* initialize */
	memset(&g_mgr, 0, sizeof(g_mgr));

	/* Default Value is 100 ms */
	g_mgr.config.sleep = 100000;
	g_mgr.config.thCnt = 2 ;

	/* Default is BroadCast */
	inet_aton("255.255.255.255", &g_mgr.config.dst_addr);
	sscanf("FF:FF:FF:FF:FF:FF", "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
	       &g_mgr.config.dst_mac_addr[0], &g_mgr.config.dst_mac_addr[1],
	       &g_mgr.config.dst_mac_addr[2], &g_mgr.config.dst_mac_addr[3],
	       &g_mgr.config.dst_mac_addr[4], &g_mgr.config.dst_mac_addr[5]);

	g_mgr.config.client_count = 1;
	g_mgr.config.subscriber_count = 1;

	g_mgr.config.sport = 68;
	g_mgr.config.dport = 67;
	g_mgr.config.corebase = 12;

	while ((opt = getopt_long(argc, argv, "i:v", long_options, &option_index)) != -1) {

		switch (opt) {
		case 0:
			switch (option_index) {
			case 0:
				/* --loop : count of sending Discovery */
				g_mgr.config.loop = atoi(optarg);
				break;

			case 1:
				/* --interval : interval of send Discovery (us) */
				g_mgr.config.sleep = atoi(optarg);
				break;

			case 2:
				/* --client-count : Count of Client */
				g_mgr.config.client_count = atoi(optarg);
				if (g_mgr.config.client_count > 254
				    || g_mgr.config.client_count < 1) {
					printf("client-count is invalid : %d\r\n",
					       g_mgr.config.client_count);
					exit(-1);
				}
				break;

			case 3:
				/* --client-gw-addr : 加入者ネットワークのGWアドレス */
				inet_aton(optarg, &g_mgr.config.client_gw_addr);
				break;

			case 4:
				/* --dst-addr : DHCP Server IP Address */
				inet_aton(optarg, &g_mgr.config.dst_addr);
				break;

			case 5:
				/* --src-addr : DHCP Client IP Address */
				inet_aton(optarg, &g_mgr.config.src_addr);
				break;

			case 6:
				/* --dst-mac-addr : DHCP Server Mac Address */
				sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				       &g_mgr.config.dst_mac_addr[0], &g_mgr.config.dst_mac_addr[1],
				       &g_mgr.config.dst_mac_addr[2], &g_mgr.config.dst_mac_addr[3],
				       &g_mgr.config.dst_mac_addr[4], &g_mgr.config.dst_mac_addr[5]);
				break;

			case 7:
				/* --src-mac-addr : DHCP Client Mac Address */
				sscanf(optarg, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
				       &g_mgr.config.src_mac_addr[0], &g_mgr.config.src_mac_addr[1],
				       &g_mgr.config.src_mac_addr[2], &g_mgr.config.src_mac_addr[3],
				       &g_mgr.config.src_mac_addr[4], &g_mgr.config.src_mac_addr[5]);
				break;

			case 8:
				/* --sport : Src Port */
				g_mgr.config.sport = atoi(optarg);
				break;

			case 9:
				/* --dport : Dest Port */
				g_mgr.config.dport = atoi(optarg);
				break;

			case 10:
				/* --subscriber-count : Subscriber Count */
				g_mgr.config.subscriber_count = atoi(optarg);
				break;

			case 11:
				/* --thread : Thread Count */
				g_mgr.config.thCnt = atoi(optarg);
				if (E_THREAD_MAX/2 < g_mgr.config.thCnt)
				{
					g_mgr.config.thCnt = E_THREAD_MAX;
					printf("#### ThreadMax Over... Change to %d\n", g_mgr.config.thCnt);
				}
				break;

            case 12:
                /* --core : CoreBase */
                g_mgr.config.corebase = atoi(optarg);
                break;

			default:
				break;
			}
			break;

		case 'i':
			/* specify interface */
			strcpy(g_mgr.config.ifname, optarg);
			break;

		case 'v':
			g_mgr.config.verbose = 1;
			break;

		default: /* '?' */
			fprintf(stderr, "Usage: %s [-c]\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	set_priority(SCHED_RR) ;

	show_manager_config();

	if (g_mgr.config.ifname[0] == '\0') {
		printf("interface name is required.\r\n");
		exit(0);
	}
	
#ifdef DPDK_USE
	// CPU 12-23
	int    rte_argc = 3;
	char   *rte_argv[4];
	
	optind = 0;
	
	rte_argv[0] = "dhcp_attack";
	rte_argv[1] = "-cFFF000"   ;
	rte_argv[2] = "-n4"        ;
	rte_argv[3] = NULL;
	
	if (rte_eal_init(rte_argc, rte_argv) <0)
	{
		DbgError("rte_eal_init() NG !!\n");
		exit(1);
	}
#endif

	start();

	exit(0);
}
