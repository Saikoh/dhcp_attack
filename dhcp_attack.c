/* 
 -v                       : ログ冗長化
 -c                       : DHCPパラメータチェック有効
 --dst-addr <Addr>        : 宛先(DHCPサーバ) IPアドレス
 --src-addr <Addr>        : 送信元(DHCP Relay)IPアドレス
 --dport                  : 宛先(DHCPサーバ)のポート番号
 --client-gw-addr <Addr>  : 加入者ホームネットワークのGW
 --subscriber-count <Num> : 加入者数
 --lease-count <Num>      : クライアント数 (MACアドレスの数)
 --mode1                  : ACK受信後1秒後にRELEASE送信、更に1秒後に再DISCOVER
 --mode2                  : ACK受信後1秒後に再REQUEST
 --burst                  : 各スレッドでwaitしない

 <指定例>

dhcp_attack --dst-addr 192.168.0.20

*/

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <signal.h>
#include <errno.h>
#include <semaphore.h>
#include <pthread.h>
#include <search.h>
#include <getopt.h>

#include <sys/socket.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rte_atomic.h>

#define likely(x)       __builtin_expect(!!(x), 1)
#define unlikely(x)     __builtin_expect(!!(x), 0)

#define BUFLEN 2000
#define USLEEP_TIME 1000 /* 10ms */

typedef struct dblink {
        struct dblink *next;
        struct dblink *prev;
} dblink_t;

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
	dblink_t link;   /* double link list    */
	u_int8_t mac[6]; /* MAC Address         */
	u_int32_t sid;   /* Server ID 格納領域  */
	struct in_addr client_addr; /* Client Address 格納領域 */
	char agent_cid[32];
	struct timeval ack_time;
	struct timeval rel_time;
} client_info_t;

typedef struct {

	sem_t sem;
	sem_t sem2;
	sem_t sem3;
	void *client_db;
	dblink_t list;   /* for release */
	dblink_t list2;  /* for re-discovert */

	struct timeval prev_time;

	int sock;
	u_int16_t sport;

	struct {
		struct {
			/* 1秒毎にクリアする */
			rte_atomic32_t tx_discover;
			rte_atomic32_t tx_request;
			rte_atomic32_t tx_release;
			rte_atomic32_t rx_offer;
			rte_atomic32_t rx_ack;
		} per_sec;

		struct {
			/* 全体 */
			rte_atomic64_t tx_discover;
			rte_atomic64_t tx_request;
			rte_atomic64_t tx_release;
			rte_atomic64_t rx_offer;
			rte_atomic64_t rx_ack;
			rte_atomic64_t tx_error;
		} all;
	} counter;

	struct {
		int verbose;
		int mode1;
		int mode2;
		int burst;
		int check_param;
		struct in_addr client_gw_addr;
		struct in_addr dst_addr;
		struct in_addr src_addr;
		u_int16_t dport;
		unsigned int lease_count;
		unsigned int subscriber_count;
	} config;
	
} manager;

manager g_mgr;

#define DEBUG_PRINTF(...) if (unlikely(g_mgr.config.verbose)) { printf(__VA_ARGS__); }

char *
mac_address_str(u_int8_t *mac)
{
	static char mac_str[80];
	sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x", 
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

	return mac_str;
}

void
show_manager_config()
{
	printf("-- Config --\n");
	printf("-v/--verbose : %s\n", g_mgr.config.verbose == 0 ? "false" : "true");
	printf("-c/--check-param : %s\n", g_mgr.config.check_param == 0 ? "false" : "true");
	printf("--lease-count : %u\r\n", g_mgr.config.lease_count);
	printf("--subscriber-count : %u\r\n", g_mgr.config.subscriber_count);
	printf("--client-gw-addr : %s\r\n", inet_ntoa(g_mgr.config.client_gw_addr));
	printf("--dst-addr : %s\r\n", inet_ntoa(g_mgr.config.dst_addr));
	printf("--src-addr : %s\r\n", inet_ntoa(g_mgr.config.src_addr));
	printf("--dport : %u\r\n", g_mgr.config.dport);
	printf("--burst : %s\r\n", g_mgr.config.burst == 0 ? "false" : "true");
	printf("--mode1 : %s\r\n", g_mgr.config.mode1 == 0 ? "false" : "true");
	printf("--mode2 : %s\r\n", g_mgr.config.mode2 == 0 ? "false" : "true");
}

int
bind_sock(void)
{
	int  sock;
        struct sockaddr_in sa;
        int ret;
	int addrlen = sizeof(sa);

        sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock < 0) {
                return -1;
	}

        sa.sin_family = AF_INET;
        sa.sin_port = 0;
        sa.sin_addr = g_mgr.config.src_addr;

        if (bind(sock,(struct sockaddr *)&sa, sizeof(sa)) < 0)
        {
                close(sock);
                return -1;
        }

	if (getsockname(sock, (struct sockaddr *)&sa, &addrlen) < 0) {
		perror("error in getsockname()\n");
	}

	printf("Bind port : %u/udp\n", ntohs(sa.sin_port));
	g_mgr.sport = ntohs(sa.sin_port);

        return(sock);
}

int
send_packet(char *buf, int len)
{
	struct sockaddr_in sa;
	int ret;

	memset (&sa, 0, sizeof sa);
	sa.sin_family = AF_INET;
	sa.sin_port   = htons(g_mgr.config.dport);
	sa.sin_addr   = g_mgr.config.dst_addr;

	ret = sendto(g_mgr.sock, buf, len, 0, (const struct sockaddr *)&sa, sizeof sa);
	if (ret < 0) {
		return -1;
	}
	
	return ret;
}

char *
search_option(u_int8_t *buf, int len, int dho)
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

u_int8_t dhcp_magic_cookie[] = { 0x63, 0x82, 0x53, 0x63 };

void
make_dhcp_header(dhcp_pkt_t *dhcp, client_info_t* client)
{
	memset(dhcp, 0 , sizeof(dhcp_pkt_t));

	dhcp->op = 1; /* Boot Request */
	dhcp->htype = 1; /* Ethernet */
	dhcp->hlen = 6;
	/* src ipが0以外の場合はDHCP Replay Agent経由を疑似するため1 */
	dhcp->hops = 1;
	dhcp->xid = client->xid;
	dhcp->secs = 0;
	/* src ipが0以外の場合はDHCP Replay Agent経由を疑似するため0 */
	dhcp->flags = 0;

	/* 加入者ホームネットワークのGWアドレス */
	dhcp->giaddr = g_mgr.config.client_gw_addr;
	
	memcpy(dhcp->chaddr, client->mac, sizeof(dhcp->chaddr));
}

void
send_discover(u_int8_t *buf, client_info_t* client)
{
	dhcp_pkt_t *dhcp;
	int len;

	int option_offset = 0;
	u_int8_t discover[] = { 53, 1, 0x01 };
	u_int8_t param_req_list[] = { 55, 6, 1, 3, 6, 15, 26, 28};
	u_int8_t relay_agent_inf[] = { 82, 0, 0x01, 0 };
	int agent_cid_len;

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

	if (send_packet(buf, len) < 0) {
		/* Send Error */
		rte_atomic64_inc(&g_mgr.counter.all.tx_error);
		return;
	}

	/* 統計 */
	rte_atomic32_inc(&g_mgr.counter.per_sec.tx_discover);
	rte_atomic64_inc(&g_mgr.counter.all.tx_discover);
}

void
send_request(u_int8_t *buf, client_info_t *client)
{
	dhcp_pkt_t *dhcp;
	int len;

	int option_offset = 0;
	u_int8_t request[] = { 53, 1, 0x03 };
	u_int8_t req_ip_addr[] = { 50, 4, 0x00, 0x00, 0x00, 0x00 };
	u_int8_t server_id[] = { 54, 4, 0x00, 0x00, 0x00, 0x00 };
	u_int8_t param_req_list[] = { 55, 6, 1, 3, 6, 15, 26, 28};
	u_int8_t relay_agent_inf[] = { 82, 0, 0x01, 0 };
	int agent_cid_len;

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

	if (send_packet(buf, len) < 0) {
		/* Send Error */
		rte_atomic64_inc(&g_mgr.counter.all.tx_error);
		return;
	}

	/* 統計 */
	rte_atomic32_inc(&g_mgr.counter.per_sec.tx_request);
	rte_atomic64_inc(&g_mgr.counter.all.tx_request);
}

void
send_release(u_int8_t *buf, client_info_t *client)
{
	dhcp_pkt_t *dhcp;
	int len;

	int option_offset = 0;
	u_int8_t release[] = { 53, 1, 0x07 };
	u_int8_t server_id[] = { 54, 4, 0x00, 0x00, 0x00, 0x00 };
	u_int8_t relay_agent_inf[] = { 82, 0, 0x01, 0 };
	int agent_cid_len;

	dhcp = (dhcp_pkt_t *)buf;

	make_dhcp_header(dhcp, client);

	/* client address */
	dhcp->ciaddr = client->client_addr;

	/* DHCP Option */

	memcpy(&dhcp->options[option_offset], dhcp_magic_cookie, sizeof(dhcp_magic_cookie));
	option_offset += sizeof(dhcp_magic_cookie);

	memcpy(&dhcp->options[option_offset], release, sizeof(release));
	option_offset += sizeof(release);

	memcpy(&server_id[2], &client->sid, sizeof(u_int32_t));
	memcpy(&dhcp->options[option_offset], server_id, sizeof(server_id));
	option_offset += sizeof(server_id);

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

	if (send_packet(buf, len) < 0) {
		/* Send Error */
		rte_atomic64_inc(&g_mgr.counter.all.tx_error);
		return;
	}

	/* 統計 */
	rte_atomic32_inc(&g_mgr.counter.per_sec.tx_release);
	rte_atomic64_inc(&g_mgr.counter.all.tx_release);
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
client_add(client_info_t *client)
{
	void *ret;

	sem_wait(&g_mgr.sem);
	
	ret = tsearch((void *)client, &g_mgr.client_db, client_comp);

	sem_post(&g_mgr.sem);

	if (ret == NULL) {
		return;
	}
}

client_info_t *
client_find(u_int32_t xid)
{
	client_info_t tmp;
	client_info_t **ret;

	tmp.xid = xid;

	sem_wait(&g_mgr.sem);

	ret = tfind(&tmp, &g_mgr.client_db, client_comp);

	sem_post(&g_mgr.sem);

	if (ret == NULL) {
		return NULL;
	}

	return *ret;
}

void
client_delete(client_info_t *client)
{
	sem_wait(&g_mgr.sem);

	tdelete((void *)client, &g_mgr.client_db, client_comp);

	sem_post(&g_mgr.sem);
}

void *
start_client(void* arg)
{
	client_info_t *client;
	u_int32_t xid;
	u_int32_t agent_cid;
	u_int8_t mac[6] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 };
	u_int8_t snd_buf[BUFLEN];
	int subscriber_count = 1;

	srand(time(NULL));
	xid = (u_int32_t)rand();

	/* Agent Circuit ID */
	/* Subscriber IDは0x12345678のような16進数の文字列 */
	agent_cid = (u_int32_t)rand();

	while(subscriber_count <= g_mgr.config.subscriber_count) {

		if (!g_mgr.config.burst) {
			/* 1 ms wait */
			usleep(USLEEP_TIME);
		}

		client = malloc(sizeof(client_info_t));
		memset(client, 0, sizeof(client));
		
		memcpy(client->mac, mac, sizeof(mac));
		client->xid = htonl(xid);

		sprintf(client->agent_cid, "0x%08x", agent_cid);

		client_add(client);

		send_discover(snd_buf, client);

		xid++;

		/* MACアドレスを加算 */
		mac[5]++;
		if (mac[5] > g_mgr.config.lease_count) {
			mac[5] = 1;
		} else {
			continue;
		}

		subscriber_count++;
		agent_cid++;
	}
}

void *
release_client(void *arg)
{
	u_int8_t buf[BUFLEN];
	client_info_t* client = NULL;
	dblink_t *tmp_link;
	long int diff_sec;
	struct timeval now;

	while(1) {

		sem_wait(&g_mgr.sem2);
		tmp_link = g_mgr.list.next;
		sem_post(&g_mgr.sem2);

		if (tmp_link == &g_mgr.list) {
			// リストが空
			goto end;
		}

		client = (client_info_t *)((void *)tmp_link - offsetof(client_info_t, link));

		gettimeofday(&now, NULL);
		diff_sec = now.tv_sec - client->ack_time.tv_sec;
		if (diff_sec <= 1) {
			// 1秒経過してしたらRelease
			goto end;
		}

		sem_wait(&g_mgr.sem2);

		// clientをdouble link listsから外す
		tmp_link->next->prev = &g_mgr.list;
		g_mgr.list.next = tmp_link->next;
		
		sem_post(&g_mgr.sem2);

		// release送信
		send_release(buf, client);

		if (g_mgr.config.mode1) {
			gettimeofday(&client->rel_time, NULL);

			/* 双方向リストの最後に追加 */
			sem_wait(&g_mgr.sem3);
			client->link.prev = g_mgr.list2.prev;
			client->link.next = &g_mgr.list2;
			g_mgr.list2.prev->next = &client->link;
			g_mgr.list2.prev = &client->link;
			sem_post(&g_mgr.sem3);
			
		} else {
			free(client);
		}
	end:
		if (!g_mgr.config.burst) {
			/* 1 ms wait */
			usleep(USLEEP_TIME);
		}
	}
}

void *
re_discover_client(void *arg)
{
	u_int8_t buf[BUFLEN];
	client_info_t* client = NULL;
	dblink_t *tmp_link;
	long int diff_sec;
	struct timeval now;

	while(1) {

		sem_wait(&g_mgr.sem3);
		tmp_link = g_mgr.list2.next;
		sem_post(&g_mgr.sem3);

		if (tmp_link == &g_mgr.list2) {
			// リストが空
			goto end;
		}

		client = (client_info_t *)((void *)tmp_link - offsetof(client_info_t, link));

		gettimeofday(&now, NULL);
		diff_sec = now.tv_sec - client->rel_time.tv_sec;
		if (diff_sec <= 1) {
			// 1秒経過してしたら再DISCOVER
			goto end;
		}

		sem_wait(&g_mgr.sem3);

		// clientをdouble link listsから外す
		tmp_link->next->prev = &g_mgr.list2;
		g_mgr.list2.next = tmp_link->next;
		
		sem_post(&g_mgr.sem3);

		client_add(client);
		send_discover(buf, client);

	end:
		if (!g_mgr.config.burst) {
			/* 1 ms wait */
			usleep(USLEEP_TIME);
		}
	}
}

void *
re_request_client(void *arg)
{
	u_int8_t buf[BUFLEN];
	client_info_t* client = NULL;
	dblink_t *tmp_link;
	long int diff_sec;
	struct timeval now;

	while(1) {

		sem_wait(&g_mgr.sem2);
		tmp_link = g_mgr.list.next;
		sem_post(&g_mgr.sem2);

		if (tmp_link == &g_mgr.list) {
			// リストが空
			goto end;
		}

		client = (client_info_t *)((void *)tmp_link - offsetof(client_info_t, link));

		gettimeofday(&now, NULL);
		diff_sec = now.tv_sec - client->ack_time.tv_sec;
		if (diff_sec <= 1) {
			// 1秒経過してしたら再Request
			goto end;
		}

		sem_wait(&g_mgr.sem2);

		// clientをdouble link listsから外す
		tmp_link->next->prev = &g_mgr.list;
		g_mgr.list.next = tmp_link->next;
		
		sem_post(&g_mgr.sem2);

		// Request送信
		client_add(client);
		send_request(buf, client);

	end:
		if (!g_mgr.config.burst) {
			/* 1 ms wait */
			usleep(USLEEP_TIME);
		}
	}
}

int
recv_dhcp_check_option(dhcp_pkt_t *dhcp, int dhcp_option_len)
{
	int i = 0;
	int check_dho[] = {1, 3, 6, 15, 51, 82, 26, 28, 0}; /* チェック対象 DHCP OPTION */
	u_int8_t *ret = NULL;

	/*
	 * Option  1 Subnet Mask
	 * Option  3 Router Option
	 * Option  6 DNS Servers
	 * Option 51 IP Address Lease Time
	 * Option 54 DHCP server Id
	 * Option 26 Interface MTU Option
	 * Option 28 Broadcast Address Option
	 * Option 82 Agent Intormation Option
	 */
	
	for (i = 0; check_dho[i] != 0; i++) {

		ret = search_option(&dhcp->options[4], dhcp_option_len, check_dho[i]);
		if (ret == NULL) {
			printf("ERROR: Cannot find option %d(0x%x),"
			       " transaction ID is 0x%x\n", check_dho[i], check_dho[i], dhcp->xid);
			return 0;
		}
	}

	return 1;
}

void
recv_dhcp(void)
{
	client_info_t* client = NULL;
	client_info_t client_tmp;
	int len;
	dhcp_pkt_t *dhcp;
	int dhcp_option_len;
	u_int8_t *message_type;
	u_int8_t buf[BUFLEN];
	u_int8_t *server_id = NULL;

	len = recvfrom(g_mgr.sock, buf, sizeof(buf), 0, NULL, NULL);
	if (len < 0) {
		return;
	}

	dhcp = (dhcp_pkt_t *)buf;

	client = client_find(dhcp->xid);

	if (client == NULL) {
		printf("ERROR: Cannot find client info from DB,"
		       " transaction ID is 0x%x\n", dhcp->xid);
		/* トランザクションIDが一致するクライアント情報がなかった */
		return;
	}

	dhcp_option_len = len - sizeof(dhcp_pkt_t) - sizeof(dhcp_magic_cookie);

	/* [53] DHCP Message Type */
	message_type = search_option(&dhcp->options[4], dhcp_option_len, 53);
	if (message_type == NULL) {
		printf("ERROR: Cannot find option %d(0x%x),"
		       " transaction ID is 0x%x\n", 53, 53, dhcp->xid);
		return;
	}

	/* [54] DHCP Server Identifier */
	server_id = search_option(&dhcp->options[4], dhcp_option_len, 54);
	if (server_id == NULL) {
		printf("ERROR: Cannot find option %d(0x%x),"
		       " transaction ID is 0x%x\n", 54, 54, dhcp->xid);
		return;
	}

	if (g_mgr.config.check_param) {
		/* -c 指定時のみチェックする */

		/* Check DHCP Option refs #1162 */
		if (!recv_dhcp_check_option(dhcp, dhcp_option_len)) {
			/* Option Check NG */
			return;
		}
	}

	if (message_type[2] == 2) {
		/* Recieved Offer */

		/* 統計 */
		rte_atomic32_inc(&g_mgr.counter.per_sec.rx_offer);
		rte_atomic64_inc(&g_mgr.counter.all.rx_offer);

		client->client_addr = dhcp->yiaddr;

		send_request(buf, client);
		
		return;
	}

	if (message_type[2] == 5) {
		/* Received Ack */

		rte_atomic32_inc(&g_mgr.counter.per_sec.rx_ack);
		rte_atomic64_inc(&g_mgr.counter.all.rx_ack);

		client_delete(client);

		if (g_mgr.config.mode1 || g_mgr.config.mode2) {

			gettimeofday(&client->ack_time, NULL);

			/* 双方向リストの最後に追加 */
			sem_wait(&g_mgr.sem2);
			client->link.prev = g_mgr.list.prev;
			client->link.next = &g_mgr.list;
			g_mgr.list.prev->next = &client->link;
			g_mgr.list.prev = &client->link;
			sem_post(&g_mgr.sem2);
		} else {
			free(client);
		}
	}
}

void
on_sig_alarm(int signum)
{
	long int diff_msec;
	struct timeval now;

	gettimeofday(&now, NULL);

	diff_msec = (now.tv_sec - g_mgr.prev_time.tv_sec) * 1000
		+ (now.tv_usec - g_mgr.prev_time.tv_usec) / 1000;

	printf("Time diff %4ld, Tx Discover %7d, "
	       "Rx Offer %7d, Tx Request %7d, "
	       "Rx Ack %7d, Tx Release %7d\n",
	       diff_msec,
	       g_mgr.counter.per_sec.tx_discover,
	       g_mgr.counter.per_sec.rx_offer,
	       g_mgr.counter.per_sec.tx_request,
	       g_mgr.counter.per_sec.rx_ack,
	       g_mgr.counter.per_sec.tx_release);

	g_mgr.prev_time = now;

	/* 毎秒毎の統計をクリア */
	rte_atomic32_init(&g_mgr.counter.per_sec.tx_discover);
	rte_atomic32_init(&g_mgr.counter.per_sec.tx_request);
	rte_atomic32_init(&g_mgr.counter.per_sec.tx_release);
	rte_atomic32_init(&g_mgr.counter.per_sec.rx_offer);
	rte_atomic32_init(&g_mgr.counter.per_sec.rx_ack);
}

void
start_timer_handler(void)
{
	struct sigaction action = { .sa_handler = on_sig_alarm, .sa_flags = 0 };
	struct itimerval timer;

	/* set signal handler */
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
on_sig_term(int signum)
{
	printf("\n");
	printf("Total Counter\n");
	printf("  Tx    : Discover %d\n", g_mgr.counter.all.tx_discover);
	printf("        : Request  %d\n", g_mgr.counter.all.tx_request);
	printf("        : Release  %d\n", g_mgr.counter.all.tx_release);
	printf("  Rx    : Offer    %d\n", g_mgr.counter.all.rx_offer);
	printf("        : Ack      %d\n", g_mgr.counter.all.rx_ack);
	printf("  ERROR : Tx error %d\n", g_mgr.counter.all.tx_error);
	exit(0);
}

void
set_term_handler(void)
{
	struct sigaction action;
	struct itimerval timer;

	/* set signal handler */
	action.sa_handler = on_sig_term;
	sigemptyset(&action.sa_mask);
	action.sa_flags = SA_NODEFER;
	if(sigaction(SIGTERM, &action, NULL) < 0){
		perror("sigaction error");
		exit(1);
	}

	action.sa_handler = on_sig_term;
	sigemptyset(&action.sa_mask);
	if(sigaction(SIGINT, &action, NULL) < 0){
		perror("sigaction error");
		exit(1);
	}
}

void
set_priority(void)
{
	int    policy_max;
	struct sched_param spp;

	policy_max = sched_get_priority_max(SCHED_RR);
	if (policy_max < 0) {
		return;
	}

	spp.sched_priority = policy_max;
	if (sched_setscheduler(0, SCHED_RR, &spp) != 0) {
		return;
	}

	printf("Set priority to SCHED_RR\n");
}

void
start(void)
{
	pthread_t thread1;
	pthread_t thread2;
	pthread_t thread3;

	set_priority();

	g_mgr.sock = bind_sock();
	if (g_mgr.sock < 0) {
		printf("Failed to bind socket\n");
		exit(0);
	}

	set_term_handler();
	start_timer_handler();

	pthread_create(&thread1, NULL, start_client, NULL);

	if (g_mgr.config.mode1) {
		pthread_create(&thread2, NULL, release_client, NULL);
		pthread_create(&thread3, NULL, re_discover_client, NULL);
	} else if (g_mgr.config.mode2) {
		pthread_create(&thread2, NULL, re_request_client, NULL);
	}

	do {
		recv_dhcp();

	} while (1);
}

int
main(int argc, char *argv[])
{
	int opt, option_index;

	struct option long_options[] = {
		{ "dst-addr", required_argument, NULL, 0 },
		{ "src-addr", required_argument, NULL, 0 },
		{ "dport", required_argument, NULL, 0 },
		{ "client-gw-addr", required_argument, NULL, 0 },
		{ "subscriber-count", required_argument, NULL, 0},
		{ "lease-count", required_argument, NULL, 0 },
		{ "burst", no_argument, NULL, 0},
		{ "mode1", no_argument, NULL, 0},
		{ "mode2", no_argument, NULL, 0},
		{ "verbose", no_argument, NULL, 'v' },
		{ "check-param", no_argument, NULL, 'c' },
		{0, 0, 0, 0},
	};

	/* initialize */
	memset(&g_mgr, 0, sizeof(g_mgr));
	sem_init(&g_mgr.sem, 1, 1);
	sem_init(&g_mgr.sem2, 1, 1);
	sem_init(&g_mgr.sem3, 1, 1);

	g_mgr.list.next = g_mgr.list.prev = &g_mgr.list;
	g_mgr.list2.next = g_mgr.list2.prev = &g_mgr.list2;

	/* Default is 192.168.0.254 */
	inet_aton("192.168.0.254", &g_mgr.config.client_gw_addr);

	g_mgr.config.lease_count = 10;
	g_mgr.config.subscriber_count = 100;

	g_mgr.config.dport = 2012;

	while ((opt = getopt_long(argc, argv, "vc", long_options, &option_index)) != -1) {

		switch (opt) {
		case 0:
			switch (option_index) {
			case 0:
				/* --dst-addr : DHCP Server IP Address */
				inet_aton(optarg, &g_mgr.config.dst_addr);
				break;

			case 1:
				/* --src-addr : DHCP Client IP Address */
				inet_aton(optarg, &g_mgr.config.src_addr);
				break;

			case 2:
				/* --dport : Dest Port */
				g_mgr.config.dport = atoi(optarg);
				break;

			case 3:
				/* --client-gw-addr : 加入者ネットワークのGWアドレス */
				inet_aton(optarg, &g_mgr.config.client_gw_addr);
				break;

			case 4:
				/* --subscriber-count : Subscriber Count */
				g_mgr.config.subscriber_count = atoi(optarg);
				break;

			case 5:
				/* --lease-count : Lease Count */
				g_mgr.config.lease_count = atoi(optarg);
				if (g_mgr.config.lease_count > 254

				    || g_mgr.config.lease_count < 1) {
					printf("lease-count is invalid : %d\r\n",
					       g_mgr.config.lease_count);
					exit(-1);
				}
				break;

			case 6:
				/* --burst : no wait, more powerfull */
				g_mgr.config.burst = 1;
				break;

			case 7:
				/* --mode1 : continuing discovery */
				g_mgr.config.mode1 = 1;
				break;

			case 8:
				/* --mode2 : continuing request */
				g_mgr.config.mode2 = 1;
				break;

			default:
				break;
			}
			break;

		case 'v':
			g_mgr.config.verbose = 1;
			break;

		case 'c':
			g_mgr.config.check_param = 1;
			break;

		default: /* '?' */
			printf("Sorry we might be obsolated that option\n", argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (g_mgr.config.dst_addr.s_addr == 0) {
		printf("--dst-addr is not set\n");
		exit(EXIT_FAILURE);
	}

	show_manager_config();

	start();

	exit(0);
}
