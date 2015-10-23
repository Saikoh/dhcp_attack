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
# gcc -pthread -O3 -o dhcp_attack dhcp_attack.c

*****************************/
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

#include <linux/in.h>
#include <linux/filter.h>
#include <linux/if_ether.h>

#if RTE_MAX_LCORE == 1
#define MPLOCKED                        /**< No need to insert MP lock prefix. */
#else
#define MPLOCKED        "lock ; "       /**< Insert MP lock prefix. */
#endif

typedef struct {
	volatile int32_t cnt; /**< An internal counter value. */
} rte_atomic32_t;


#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define BUFLEN 2000

typedef struct {
        u_int8_t dst[6];
        u_int8_t src[6];
        u_int16_t type;
} ether_hdr_t;

typedef struct {
        u_int8_t  fvhl;              /* header length, version */
        u_int8_t  tos;               /* type of service */
        int16_t   len;               /* total length */
        u_int16_t id;                /* identification */
        int16_t   off;               /* fragment offset field */
#define IP_DF 0x4000                    /* dont fragment flag */
#define IP_MF 0x2000                    /* more fragments flag */
#define IP_OFFMASK 0x1fff               /* mask for fragmenting bits */
        u_int8_t  ttl;               /* time to live */
        u_int8_t  p;                 /* protocol */
        u_int16_t sum;               /* checksum */
        struct    in_addr src, dst; /* source and dest address */
} ip_hdr_t;

#define IP_V(iph)        ((iph)->fvhl >> 4)
#define IP_HL(iph)       (((iph)->fvhl & 0x0F) << 2)
#define IP_V_SET(iph,x)  ((iph)->fvhl = ((iph)->fvhl & 0x0F) | ((x) << 4))
#define IP_HL_SET(iph,x) ((iph)->fvhl = ((iph)->fvhl & 0xF0) | (((x) >> 2) & 0x0F))

typedef struct {
        u_int16_t sport;             /* source port */
        u_int16_t dport;             /* destination port */
        u_int16_t ulen;              /* udp length */
        u_int16_t sum;               /* udp checksum */
} udp_hdr_t;

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
	u_int32_t xid;   /* DHCP Transaction ID */
	u_int8_t mac[6]; /* MAC Address         */
	u_int32_t sid;   /* Server ID 格納領域 */
	struct in_addr client_addr; /* Client Address 格納領域 */
	char agent_cid[32];
} client_info_t;

typedef struct {

	struct timeval prev_time;

	int status;
	int start;
	int finished;
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
		char ifname[80];
		u_int8_t dst_mac_addr[6];
		u_int8_t src_mac_addr[6];
	} config;

} manager;

manager g_mgr;

#define E_THREAD_MAX    10  // 仮に 5とした
typedef struct
{
	unsigned int  stag;
	unsigned int  ctag;
	u_int8_t  mac_addr[6]; // chaddr[]のベースの値
	unsigned int  loop ;  // このスレッドが送信する Discoverの数
	unsigned int  fst ;

	sem_t sem;
	void *client_db;

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

} thData;

thData  g_thData[E_THREAD_MAX];


#define DEBUG_PRINTF(...) if (unlikely(g_mgr.config.verbose)) { printf(__VA_ARGS__); }


#define log_printf(LEVEL, FMT, ARGs...) \
  printf(FMT, ##ARGs)

#define DbgError    printf

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
	printf("--interval : %u [us] \r\n", g_mgr.config.sleep);
	printf("--client-count : %u\r\n", g_mgr.config.client_count);
	printf("--subscriber-count : %u\r\n", g_mgr.config.subscriber_count);
	printf("--client-gw-addr : %s\r\n", addr_str(g_mgr.config.client_gw_addr));
	printf("--dst-addr : %s\r\n", addr_str(g_mgr.config.dst_addr));
	printf("--src-addr : %s\r\n", addr_str(g_mgr.config.src_addr));
	printf("--dst-mac-addr : %s\r\n", mac_address_str(g_mgr.config.dst_mac_addr));
	printf("--src-mac-addr : %s\r\n", mac_address_str(g_mgr.config.src_mac_addr));
	printf("--sport : %u\r\n", g_mgr.config.sport);
	printf("--dport : %u\r\n", g_mgr.config.dport);
}

/* Compute the easy part of the checksum on a range of bytes. */
u_int32_t
checksum(unsigned char *buf, unsigned nbytes, u_int32_t sum)
{
        unsigned i;

        /* Checksum all the pairs of bytes first... */
        for (i = 0; i < (nbytes & ~1U); i += 2) {
                sum += (u_int16_t) ntohs(*((u_int16_t *)(buf + i)));
                /* Add carry. */
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }

        /* If there's a single byte left over, checksum it, too.   Network
           byte order is big-endian, so the remaining byte is the high byte. */
        if (i < nbytes) {
                sum += buf [i] << 8;
                /* Add carry. */
                if (sum > 0xFFFF)
                        sum -= 0xFFFF;
        }

        return sum;
}

/* Finish computing the checksum, and then put it into network byte order. */
u_int32_t
wrapsum (u_int32_t sum)
{
        sum = ~sum & 0xFFFF;
        return htons(sum);
}


#if 0
void
bind_sock(void)
{
	int s;
	struct sockaddr sa;
	struct sock_fprog p;
	struct sock_filter filter[] = {
		/* Make sure this is an IP packet... */
		BPF_STMT (BPF_LD + BPF_H + BPF_ABS, 12),
		BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, 0x0800, 0, 8),

		/* Make sure it's a UDP packet... */
		BPF_STMT (BPF_LD + BPF_B + BPF_ABS, 23),
		BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, 17, 0, 6),

		/* Make sure this isn't a fragment... */
		BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 20),
		BPF_JUMP(BPF_JMP + BPF_JSET + BPF_K, 0x1fff, 4, 0),

		/* Get the IP header length... */
		BPF_STMT (BPF_LDX + BPF_B + BPF_MSH, 14),

		/* Make sure it's to the right port... */
		BPF_STMT (BPF_LD + BPF_H + BPF_IND, 16),
		BPF_JUMP (BPF_JMP + BPF_JEQ + BPF_K, 68, 0, 1),

		/* If we passed all the tests, ask for the whole packet. */
		BPF_STMT(BPF_RET+BPF_K, (u_int)-1),

		/* Otherwise, drop it. */
		BPF_STMT(BPF_RET+BPF_K, 0),
	};

	int filter_len = sizeof(filter) / sizeof(struct sock_filter);

	if ((s = socket(PF_PACKET, SOCK_PACKET, htons((short)ETH_P_ALL))) < 0) {
		DEBUG_PRINTF("error\r\n");
		return;
	}

	memset (&sa, 0, sizeof sa);
	sa.sa_family = AF_PACKET;
	strncpy (sa.sa_data, (const char *)g_mgr.config.ifname, sizeof(sa.sa_data));

	if (bind (s, &sa, sizeof(sa))) {
		DEBUG_PRINTF("error\r\n");
		return;
	}

        memset(&p, 0, sizeof(p));

        /* Set up the bpf filter program structure.    This is defined in
           bpf.c */
        p.len = filter_len;
        p.filter = filter;

	/* sportで受信するパケット以外は廃棄 */
	filter[8].k = g_mgr.config.sport;

	/* Linux Packet Filter */
        if (setsockopt (s, SOL_SOCKET, SO_ATTACH_FILTER, &p, sizeof(p)) < 0) {
		return;
        }

	g_mgr.sock = s;
}
#else
int
bind_sock(void)
{
	int  sock;
	struct sockaddr_in sa;
	int ret;
	int yes = 1;

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	if (0>sock)
		return -1;

	if (setsockopt(sock, SOL_SOCKET, SO_NO_CHECK, (const char *)&yes, sizeof(yes)) != 0) {
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
	return(sock);
}
#endif


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

    /* For some reason, SOCK_PACKET sockets can't be connected,
       so we have to do a sentdo every time. */
    memset (&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_port   = htons(g_mgr.config.dport);
    sa.sin_addr   = g_mgr.config.dst_addr;

    ret = sendto(sock, buf, len, 0, (const struct sockaddr *)&sa, sizeof sa);

    if (ret < 0) {
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

void
make_dhcp_header(dhcp_pkt_t *dhcp, client_info_t* client)
{
	memset(dhcp, 0 , sizeof(dhcp_pkt_t));

	dhcp->op = 1; /* Boot Request */
	dhcp->htype = 1; /* Ethernet */
	dhcp->hlen = 6;
	/* src ipが0以外の場合はDHCP Replay Agent経由を疑似するため1 */
	dhcp->hops = is_dhcp_relay_mode() == 1 ? 1 : 0;
	dhcp->xid = client->xid;
	dhcp->secs = 0;
	/* src ipが0以外の場合はDHCP Replay Agent経由を疑似するため0 */
	dhcp->flags = is_dhcp_relay_mode() == 0 ? 0x8000 : 0;

	if (is_dhcp_relay_mode()) {
		/* 加入者ホームネットワークのGWアドレス */
		dhcp->giaddr = g_mgr.config.client_gw_addr;
	}

	memcpy(dhcp->chaddr, client->mac, sizeof(client->mac));
}

int
send_discover(int sock, u_int8_t *buf, client_info_t* client)
{
	dhcp_pkt_t *dhcp;
	int len;

	int option_offset = 0;
	u_int8_t discover[] = { 53, 1, 0x01 };
	u_int8_t param_req_list[] = { 55, 3, 0x01, 0x03, 0x06 };
	u_int8_t relay_agent_inf[] = { 82, 0, 0x01, 0 };
	int agent_cid_len;

	//dhcp = (dhcp_pkt_t *)(buf + sizeof(ether_hdr_t) + sizeof(ip_hdr_t) + sizeof(udp_hdr_t));
	dhcp = (dhcp_pkt_t *)buf;

	make_dhcp_header(dhcp, client);

	/* DHCP Option */

	memcpy(&dhcp->options[option_offset], dhcp_magic_cookie, sizeof(dhcp_magic_cookie));
	option_offset += sizeof(dhcp_magic_cookie);

	memcpy(&dhcp->options[option_offset], discover, sizeof(discover));
	option_offset += sizeof(discover);

	memcpy(&dhcp->options[option_offset], param_req_list, sizeof(param_req_list));
	option_offset += sizeof(param_req_list);

	agent_cid_len = strlen(client->agent_cid);
	relay_agent_inf[1] = agent_cid_len + 2; /* Length of DHCP Relay Agent Information Option */
	relay_agent_inf[3] = agent_cid_len;     /* Length of Agent Information Field */
	memcpy(&dhcp->options[option_offset], relay_agent_inf, sizeof(relay_agent_inf));
	option_offset += sizeof(relay_agent_inf);

	/* Agent Circuit ID Sub-option */
	memcpy(&dhcp->options[option_offset], client->agent_cid, agent_cid_len);
	option_offset += agent_cid_len;

	dhcp->options[option_offset] = 0xFF; /* Option End */
	option_offset++;

	/* calc udp payload length */
	len = option_offset + sizeof(dhcp_pkt_t);

	return send_packet(sock, buf, len);
}

int
send_request(int sock, u_int8_t *buf, client_info_t *client)
{
	dhcp_pkt_t *dhcp;
	int len;

	int option_offset = 0;
	u_int8_t request[] = { 53, 1, 0x03 };
	u_int8_t req_ip_addr[] = { 50, 4, 0x00, 0x00, 0x00, 0x00 };
	u_int8_t server_id[] = { 54, 4, 0x00, 0x00, 0x00, 0x00 };
	u_int8_t param_req_list[] = { 55, 3, 0x01, 0x03, 0x06 };
	u_int8_t relay_agent_inf[] = { 82, 0, 0x01, 0 };
	int agent_cid_len;

	//dhcp = (dhcp_pkt_t *)(buf + sizeof(ether_hdr_t) + sizeof(ip_hdr_t) + sizeof(udp_hdr_t));
	dhcp = (dhcp_pkt_t *)buf;

	make_dhcp_header(dhcp, client);

	/* DHCP Option */

	memcpy(&dhcp->options[option_offset], dhcp_magic_cookie, sizeof(dhcp_magic_cookie));
	option_offset += sizeof(dhcp_magic_cookie);

	memcpy(&dhcp->options[option_offset], request, sizeof(request));
	option_offset += sizeof(request);

	memcpy(&req_ip_addr[2], &client->client_addr, sizeof(struct in_addr));
	memcpy(&dhcp->options[option_offset], req_ip_addr, sizeof(req_ip_addr));
	option_offset += sizeof(req_ip_addr);

	memcpy(&server_id[2], &client->sid, sizeof(u_int32_t));
	memcpy(&dhcp->options[option_offset], server_id, sizeof(server_id));
	option_offset += sizeof(server_id);

	memcpy(&dhcp->options[option_offset], param_req_list, sizeof(param_req_list));
	option_offset += sizeof(param_req_list);

	agent_cid_len = strlen(client->agent_cid);
	relay_agent_inf[1] = agent_cid_len + 2; /* Length of DHCP Relay Agent Information Option */
	relay_agent_inf[3] = agent_cid_len;     /* Length of Agent Information Field */
	memcpy(&dhcp->options[option_offset], relay_agent_inf, sizeof(relay_agent_inf));
	option_offset += sizeof(relay_agent_inf);

	/* Agent Circuit ID Sub-option */
	memcpy(&dhcp->options[option_offset], client->agent_cid, agent_cid_len);
	option_offset += agent_cid_len;

	dhcp->options[option_offset] = 0xFF; /* Option End */
	option_offset++;

	/* calc udp payload length */
	len = option_offset + sizeof(dhcp_pkt_t);

	return send_packet(sock, buf, len);
}

void
signal_handler(int signum)
{
	long int inverval;
	struct timeval now;
	unsigned long  per_discover=0, per_request=0, per_ack=0;
	unsigned long  all_discover=0, all_request=0, all_ack=0, wait_offer=0, wait_ack=0;
	int i ;

	gettimeofday(&now, NULL);
	for (i=0; i<g_mgr.config.thCnt; i++)
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

	inverval = (now.tv_sec - g_mgr.prev_time.tv_sec) * 1000 + (now.tv_usec - g_mgr.prev_time.tv_usec) / 1000;

	printf("Interval %ld : Send Discover %lu/%lu, Request %lu/%lu, Received Ack %lu/%lu, Waiting Offer %lu, Ack %lu\r\n",
	       inverval,
	       per_discover, all_discover,
	       per_request, all_request,
	       per_ack, all_ack,
	       wait_offer, wait_ack);

	g_mgr.prev_time = now;

	/* 終了判定 */
	if (!g_mgr.finished && now.tv_sec - g_mgr.finished_time.tv_sec > 5) {

		/* 全てのDiscoverを送信して5秒後に終了 */
		for (i=0; i<g_mgr.config.thCnt; i++)
		{
		    printf("id-%d : Send Discover %lu, Request %lu, Received Ack %lu, Waiting Offer %lu, Ack %lu\r\n",
		       i,
		       g_thData[i].counter.all.send_discover.cnt,
		       g_thData[i].counter.all.send_request.cnt,
		       g_thData[i].counter.all.received_ack.cnt,
		       g_thData[i].counter.all.waiting_offer.cnt, g_thData[i].counter.all.waiting_ack.cnt);
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

void
client_show(client_info_t* client)
{
	DEBUG_PRINTF("client 0x%p", client);
	DEBUG_PRINTF("  xid = (0x%x)\r\n", ntohl(client->xid));
	DEBUG_PRINTF("  mac = %02x:%02x:%02x:%02x:%02x:%02x\r\n",
	       client->mac[0], client->mac[1], client->mac[2],
	       client->mac[3], client->mac[4], client->mac[5]);
}

int
client_comp(const void *pa, const void *pb)
{
	const client_info_t *cli_a = pa;
	const client_info_t *cli_b = pb;

	if (cli_a->xid < cli_b->xid) {
		return -1;
	} else if (cli_a->xid > cli_b->xid) {
		return 1;
	}

	return 0;
}

void
client_walk_show(const void *nodep, const VISIT which, const int depth)
{
	client_info_t *cli;

	switch (which) {
	case preorder:
		break;
	case postorder:
		cli = *(client_info_t **) nodep;
		client_show(cli);
		break;
	case endorder:
		break;
	case leaf:
		cli = *(client_info_t **) nodep;
		client_show(cli);
		break;
	}
}

void
client_add(client_info_t *client, void  *a_cliDb, sem_t *a_sem)
{
	void *ret;

	sem_wait(a_sem);

	ret = tsearch((void *)client, a_cliDb, client_comp);

	sem_post(a_sem);

	if (ret == NULL) {
		return;
	}
}

client_info_t *
client_find(u_int32_t xid, void  *a_cliDb, sem_t *a_sem)
{
	client_info_t tmp;
	client_info_t **ret;

	tmp.xid = xid;

	sem_wait(a_sem);

	ret = tfind(&tmp, a_cliDb, client_comp);

	sem_post(a_sem);

	if (ret == NULL) {
		return NULL;
	}

	return *ret;
}

void
client_delete(client_info_t *client, void  *a_cliDb, sem_t *a_sem)
{
	sem_wait(a_sem);

	tdelete((void *)client, a_cliDb, client_comp);

	sem_post(a_sem);
}


void
recv_dhcp(thData  *a_thData, int flags)
{
	client_info_t client_tmp;
	client_info_t* client = &client_tmp;
	int len;
	dhcp_pkt_t *dhcp;
	int dhcp_option_len;
	u_int8_t *message_type;
	u_int8_t buf[BUFLEN];
	int  t_ret ;
	int  i ;

	do
	{
		len = recvfrom(a_thData->sock, buf, sizeof(buf), flags, NULL, NULL);

		if (0 >= len)
		{
			break;
		}

		dhcp = (dhcp_pkt_t *)buf;

#if 0
		client = client_find(dhcp->xid, &a_thData->client_db, &a_thData->sem);

		if (client == NULL) {
			/* トランザクションIDが一致するクライアント情報がなかった */
			DbgError("#### No Client Message Recv. xid=%#x\n", dhcp->xid);
			continue;
		}
#endif
		//dhcp_option_len = ntohs(udp->ulen) - sizeof(udp_hdr_t) - sizeof(dhcp_pkt_t) - sizeof(dhcp_magic_cookie);
		dhcp_option_len = len ;
		message_type = serch_option(&dhcp->options[4], dhcp_option_len, 53);
		if (message_type == NULL) {
			/* メッセージタイプがない */
			DbgError("#### No MessageType Message Recv. xid=%#x\n", dhcp->xid);
			continue;
		}

		dhcp_show(dhcp, message_type[2]);

		if (message_type[2] == 2) {
			/* Recieved Offer */
			u_int8_t *server_id = NULL;
			u_int8_t *a_agentCid = NULL;

			client->xid = dhcp->xid ;
			memcpy(client->mac, dhcp->chaddr, sizeof(client->mac));

			client->client_addr = dhcp->yiaddr;

			server_id = serch_option(&dhcp->options[4], dhcp_option_len, 54);
			if (server_id != NULL) {
				memcpy(&client->sid, &server_id[2], sizeof(u_int32_t));
			} else {
				memset(&client->sid, 0, sizeof(u_int32_t));
			}

			a_agentCid = serch_option(&dhcp->options[4], dhcp_option_len, 82);
			if (NULL != a_agentCid)
			{
				memcpy(client->agent_cid, &a_agentCid[4], a_agentCid[3]);
			}
			else
			{
				memset(client->agent_cid, 0, sizeof(client->agent_cid));
			}

			send_request(a_thData->sock, buf, client);

			/* 統計★要排他★ */
			rte_atomic32_inc(&a_thData->counter.per_sec.send_request);
			rte_atomic32_inc(&a_thData->counter.all.send_request);
			rte_atomic32_dec(&a_thData->counter.all.waiting_offer);
			rte_atomic32_inc(&a_thData->counter.all.waiting_ack);
		}
		else if (message_type[2] == 5) {
			/* Received Ack★要排他★ */
			//client_delete(client, &a_thData->client_db, &a_thData->sem);
			//free(client);
			rte_atomic32_inc(&a_thData->counter.per_sec.received_ack);
			rte_atomic32_inc(&a_thData->counter.all.received_ack);
			rte_atomic32_dec(&a_thData->counter.all.waiting_ack);
		}
	} while(0);
}

void *
start_client(void* arg)
{
	client_info_t client_tmp;
	client_info_t *client = &client_tmp;
	u_int32_t xid;
	u_int8_t mac[6] ; //= { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	u_int8_t snd_buf[BUFLEN];
	unsigned int stag ;
	unsigned int ctag ;
	int subscriver_count = 1;
	unsigned int tmp = 100000;

	thData  *a_thData = (thData*)arg;
	stag = a_thData->stag ;
	ctag = a_thData->ctag ;
	memcpy(mac, a_thData->mac_addr, sizeof(mac));
	mac[5] = 1 ;

	srand(time(NULL));
	xid = (u_int32_t)rand();

	while(!g_mgr.start)
		usleep(10);

	printf("Start xid=%#x stag=%d, ctag=%d, mac=%02x:%02x:%02x:%02x:%02x:%02x\r\n",
			xid, stag,ctag, mac[0],mac[1],mac[2],mac[3],mac[4],a_thData->mac_addr[5]);
	while(a_thData->loop)
	{
		if (g_mgr.config.sleep+(tmp/10000) != 0)
		{
			usleep(g_mgr.config.sleep+(tmp/10000));
			if (tmp) tmp--;

		}

		//client = malloc(sizeof(client_info_t));
		memset(client, 0, sizeof(client));

		memcpy(client->mac, mac, sizeof(mac));
		client->xid = htonl(xid);

		/* Agent Circuit ID */
		sprintf(client->agent_cid, "NEC-BRAS/QinQ=%u-%u", stag, ctag);

		//client_add(client, &a_thData->client_db, &a_thData->sem);

		send_discover(a_thData->sock, snd_buf, client);

		/* 統計 */
		rte_atomic32_inc(&a_thData->counter.per_sec.send_discover);
		rte_atomic32_inc(&a_thData->counter.all.send_discover);
		rte_atomic32_inc(&a_thData->counter.all.waiting_offer);

		xid++;
		a_thData->loop--;

		/* ctagを加算 */
		subscriver_count++;
		if (subscriver_count > g_mgr.config.subscriber_count) {
			subscriver_count = 1;
			ctag = a_thData->ctag;
			/* MACアドレスを加算 */
			mac[5]++;
			if (mac[5] > g_mgr.config.client_count) {
				mac[5] = 1;
			}

		} else {
			ctag++;
		}

		recv_dhcp(a_thData, MSG_DONTWAIT);
	}

	printf("Finished\r\n");

	gettimeofday(&g_mgr.finished_time, NULL);
	g_mgr.finished--;

	while (a_thData->counter.all.waiting_offer.cnt && a_thData->counter.all.waiting_ack.cnt)
	{
		recv_dhcp(a_thData, 0);
	}
}

void *
recv_thread(void *arg)
{
	int  t_ret ;
	thData  *a_thData = (thData*)arg;

	while(g_mgr.status)
	{
		recv_dhcp(a_thData, 0);
	}
}



void
start(void)
{
	pthread_t thread;
	int i ;

	g_mgr.status = 1;

	for (i=0; i<g_mgr.config.thCnt; i++)
	{
		memset(&g_thData[i], 0, sizeof(g_thData[i]));

		sem_init(&g_thData[i].sem, 1, 1);
		g_thData[i].stag = 200 + g_mgr.config.subscriber_count*i;
		g_thData[i].ctag = 1 ;
		g_thData[i].mac_addr[0] = 0x4c ;
		g_thData[i].mac_addr[1] = (g_thData[i].stag>>24) & 0xFF;
		g_thData[i].mac_addr[2] = (g_thData[i].stag>>16) & 0xFF;
		g_thData[i].mac_addr[3] = (g_thData[i].stag>> 8) & 0xFF;
		g_thData[i].mac_addr[4] = g_thData[i].stag       & 0xFF ;
		//g_thData[i].mac_addr[5] = g_thData[i].ctag;

		g_thData[i].loop = (g_mgr.config.loop+g_mgr.config.thCnt-1)/g_mgr.config.thCnt;

		g_thData[i].sock = bind_sock() ;
		if (0>g_thData[i].sock)
		{
			printf("#### socket err...####\n");
			exit(0);
		}

		pthread_create(&thread, NULL, recv_thread, &g_thData[i]);
		pthread_create(&thread, NULL, start_client, &g_thData[i]);
		g_mgr.finished++;
	}

	start_timer_handler();
	g_mgr.start = 1;

	do {
		sleep(1) ;
	} while (1);
}

int
main(int argc, char *argv[])
{
	int opt, option_index;

	struct option long_options[] = {
		{ "loop", required_argument, NULL, 0 },
		{ "interval", required_argument, NULL, 0 },
		{ "client-count", required_argument, NULL, 0 },
		{ "client-gw-addr", required_argument, NULL, 0 },
		{ "dst-addr", required_argument, NULL, 0 },
		{ "src-addr", required_argument, NULL, 0 },
		{ "dst-mac-addr", required_argument, NULL, 0 },
		{ "src-mac-addr", required_argument, NULL, 0 },
		{ "sport", required_argument, NULL, 0 },
		{ "dport", required_argument, NULL, 0 },
		{ "subscriber-count", required_argument, NULL, 0},
		{ "thread", required_argument, NULL, 0},
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
				if (E_THREAD_MAX < g_mgr.config.thCnt)
				{
					g_mgr.config.thCnt = E_THREAD_MAX;
					printf("#### ThreadMax Over... Change to %d\n", g_mgr.config.thCnt);
				}
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

	start();

	exit(0);
}
