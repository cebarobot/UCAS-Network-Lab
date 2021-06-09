#include "nat.h"
#include "ip.h"
#include "icmp.h"
#include "tcp.h"
#include "rtable.h"
#include "log.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

static struct nat_table nat;

// get the interface from iface name
static iface_info_t *if_name_to_iface(const char *if_name)
{
	iface_info_t *iface = NULL;
	list_for_each_entry(iface, &instance->iface_list, list) {
		if (strcmp(iface->name, if_name) == 0)
			return iface;
	}

	log(ERROR, "Could not find the desired interface according to if_name '%s'", if_name);
	return NULL;
}

// determine the direction of the packet, DIR_IN / DIR_OUT / DIR_INVALID
static int get_packet_direction(char *packet)
{
	fprintf(stdout, "TODO: determine the direction of this packet.\n");

	struct iphdr * hdr = packet_to_ip_hdr(packet);
	u32 saddr = ntohl(hdr->saddr);
	u32 daddr = ntohl(hdr->daddr);
	rt_entry_t * s_entry = longest_prefix_match(saddr);
	rt_entry_t * d_entry = longest_prefix_match(daddr);
	iface_info_t * s_iface = s_entry->iface;
	iface_info_t * d_iface = d_entry->iface;
	if (s_iface == nat.internal_iface && d_iface == nat.external_iface) {
		return DIR_OUT;
	} else if (s_iface == nat.external_iface && daddr == nat.external_iface->ip) {
		return DIR_IN;
	}
	return DIR_INVALID;
}

u16 assign_external_port() {
	for (int i = NAT_PORT_MIN; i < NAT_PORT_MAX; i++) {
		if (nat.assigned_ports[i] == 0) {
			nat.assigned_ports[i] = 1;
			return i;
		}
	}
	return 0;
}

u8 get_hash_ip_port(u32 ip, u16 port) {
	ip_port_pair_t ip_port;
	ip_port.ip = ip;
	ip_port.port = port;
	return hash8((void *) &ip_port, sizeof(ip_port_pair_t));
}

struct nat_mapping * lookup_nat_mapping(u32 remote_ip, u16 remote_port, u32 nat_ip, u16 nat_port, int dir) {
	u8 hash = get_hash_ip_port(remote_ip, remote_port);
	struct nat_mapping * pos = NULL;
	if (dir == DIR_IN) {
		list_for_each_entry(pos, &nat.nat_mapping_list[hash], list) {
			if (pos->remote_ip == remote_ip && pos->remote_port && 
				pos->external_ip == nat_ip && pos->external_port == nat_port
			) {
				return pos;
			}
		}
	} else if (dir == DIR_OUT) {
		list_for_each_entry(pos, &nat.nat_mapping_list[hash], list) {
			if (pos->remote_ip == remote_ip && pos->remote_port && 
				pos->internal_ip == nat_ip && pos->internal_port == nat_port
			) {
				return pos;
			}
		}
	}
	return NULL;
}

struct nat_mapping * setup_nat_mapping(u32 remote_ip, u16 remote_port, u32 nat_ip, u16 nat_port, int dir) {
	u8 hash = get_hash_ip_port(remote_ip, remote_port);
	if (dir == DIR_IN) {
		// lookup dnat rule
		struct dnat_rule * rule_p = NULL, * rule_match = NULL;
		list_for_each_entry(rule_p, &nat.rules, list) { 
			if (rule_p->external_ip == nat_ip && rule_p->external_port == nat_port) {
				rule_match = rule_p;
				break;
			}
		}
		if (!rule_match) {
			return NULL;
		}

		struct nat_mapping * new_mapping = malloc(sizeof(struct nat_mapping));
		bzero(new_mapping, sizeof(struct nat_mapping));
		new_mapping->external_ip = rule_match->external_ip;
		new_mapping->external_port = rule_match->external_port;
		new_mapping->internal_ip = rule_match->internal_ip;
		new_mapping->internal_port = rule_match->internal_port;
		new_mapping->remote_ip = remote_ip;
		new_mapping->remote_port = remote_port;
		
		list_add_tail(&new_mapping->list, &nat.nat_mapping_list[hash]);
		return new_mapping;
	} else if (dir == DIR_OUT) {
		// assign external port
		struct nat_mapping * new_mapping = malloc(sizeof(struct nat_mapping));
		bzero(new_mapping, sizeof(struct nat_mapping));
		new_mapping->external_ip = nat.external_iface->ip;
		new_mapping->external_port = assign_external_port();
		new_mapping->internal_ip = nat_ip;
		new_mapping->internal_port = nat_port;
		new_mapping->remote_ip = remote_ip;
		new_mapping->remote_port = remote_port;

		list_add_tail(&new_mapping->list, &nat.nat_mapping_list[hash]);
		return new_mapping;
	}
	return NULL;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	fprintf(stdout, "TODO: do translation for this packet.\n");
	
	struct iphdr * ip_hdr = packet_to_ip_hdr(packet);
	struct tcphdr * tcp_hdr = (void *) IP_DATA(ip_hdr);
	u32 pkt_seq_end = tcp_seq_end(ip_hdr, tcp_hdr);
	u32 pkt_ack = ntohl(tcp_hdr->ack);

	u32 remote_ip, nat_ip;
	u16 remote_port, nat_port;
	if (dir == DIR_IN) {
		remote_ip = ntohl(ip_hdr->saddr);
		remote_port = ntohs(tcp_hdr->sport);
		nat_ip = ntohl(ip_hdr->daddr);
		nat_port = ntohs(tcp_hdr->dport);
	} else if (dir == DIR_OUT) {
		remote_ip = ntohl(ip_hdr->daddr);
		remote_port = ntohs(tcp_hdr->dport);
		nat_ip = ntohl(ip_hdr->saddr);
		nat_port = ntohs(tcp_hdr->sport);
	}

	struct nat_mapping * mapping_entry = 
			lookup_nat_mapping(remote_ip, remote_port, nat_ip, nat_port, dir);
	if (!mapping_entry && (tcp_hdr->flags & TCP_SYN)) {
		mapping_entry = setup_nat_mapping(remote_ip, remote_port, nat_ip, nat_port, dir);
	}
	if (!mapping_entry) {
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return;
	}

	u32 * conn_seq_end = NULL;
	u32 * conn_ack = NULL;
	u32 * conn_fin = NULL;

	if (dir == DIR_IN) {
		ip_hdr->daddr = htonl(mapping_entry->internal_ip);
		tcp_hdr->dport = htons(mapping_entry->internal_port);

		if (pkt_seq_end > mapping_entry->conn.external_seq_end) {
			mapping_entry->conn.external_seq_end = pkt_seq_end;
		}
		if (pkt_ack > mapping_entry->conn.external_fin) {
			mapping_entry->conn.external_ack = pkt_ack;
		}
		if (tcp_hdr->flags & TCP_FIN) {
			mapping_entry->conn.external_fin = 1;
		}
	} else if (dir == DIR_OUT) {
		ip_hdr->saddr = htonl(mapping_entry->external_ip);
		tcp_hdr->sport = htons(mapping_entry->external_port);

		if (pkt_seq_end > mapping_entry->conn.internal_seq_end) {
			mapping_entry->conn.internal_seq_end = pkt_seq_end;
		}
		if (pkt_ack > mapping_entry->conn.internal_fin) {
			mapping_entry->conn.internal_ack = pkt_ack;
		}
		if (tcp_hdr->flags & TCP_FIN) {
			mapping_entry->conn.internal_fin = 1;
		}
	}
	mapping_entry->update_time = time(NULL);

	ip_hdr->checksum = ip_checksum(ip_hdr);
	tcp_hdr->checksum = tcp_checksum(ip_hdr, tcp_hdr);

	ip_forward_packet(htonl(ip_hdr->daddr), packet, len);
}

void nat_translate_packet(iface_info_t *iface, char *packet, int len)
{
	int dir = get_packet_direction(packet);
	if (dir == DIR_INVALID) {
		log(ERROR, "invalid packet direction, drop it.");
		icmp_send_packet(packet, len, ICMP_DEST_UNREACH, ICMP_HOST_UNREACH);
		free(packet);
		return ;
	}

	struct iphdr *ip = packet_to_ip_hdr(packet);
	if (ip->protocol != IPPROTO_TCP) {
		log(ERROR, "received non-TCP packet (0x%0hhx), drop it", ip->protocol);
		free(packet);
		return ;
	}

	do_translation(iface, packet, len, dir);
}

// check whether the flow is finished according to FIN bit and sequence number
// XXX: seq_end is calculated by `tcp_seq_end` in tcp.h
static int is_flow_finished(struct nat_connection *conn)
{
    return (conn->internal_fin && conn->external_fin) && \
            (conn->internal_ack >= conn->external_seq_end) && \
            (conn->external_ack >= conn->internal_seq_end);
}

// nat timeout thread: find the finished flows, remove them and free port
// resource
void *nat_timeout()
{
	while (1) {
		sleep(1);
		// TODO:
		fprintf(stdout, "TODO: sweep finished flows periodically.\n");
		time_t now = time(NULL);
		for (int i = 0; i < HASH_8BITS; i++) {
			struct nat_mapping * entry = NULL, * entry_q = NULL;
			list_for_each_entry_safe(entry, entry_q, &nat.nat_mapping_list[i], list) {
				if (is_flow_finished(&entry->conn) || now - entry->update_time > TCP_ESTABLISHED_TIMEOUT) {
					log(DEBUG, "sweep a nat");
					list_delete_entry(&entry->list);
					free(entry);
				}
			}
		}
	}

	return NULL;
}

int parse_config(const char *filename)
{
	fprintf(stdout, "TODO: parse config file, including i-iface, e-iface (and dnat-rules if existing).\n");
	FILE * conf_file = fopen(filename, "r");

	if (conf_file == NULL) {
		log(ERROR, "cannot open config file.");
		return 1;
	}

	static char buff[100];
	static char name[16];

	printf("====config:\n");
	while (fgets(buff, 100, conf_file)) {
		char * pos = strchr(buff, ':');
		if (pos == NULL) {
			continue;
		}
		if (strncmp(buff, "internal-iface", pos - buff) == 0) {
			sscanf(pos + 2, "%s", name);
			nat.internal_iface = if_name_to_iface(name);
			if (nat.internal_iface) {
				printf("internal-iface: %s\n", nat.internal_iface->name);
			}
		} else if (strncmp(buff, "external-iface", pos - buff) == 0) {
			sscanf(pos + 2, "%s", name);
			nat.external_iface = if_name_to_iface(name);
			if (nat.external_iface) {
				printf("external-iface: %s\n", nat.external_iface->name);
			}
		} else if (strncmp(buff, "dnat-rules", pos - buff) == 0) {
			u32 out_ip, in_ip;
			u16 out_port, in_port;
			int rs = sscanf(pos + 2, IP_FMT ":%hu %*s " IP_FMT ":%hu", 
					HOST_IP_SCAN_STR(out_ip), &out_port, HOST_IP_SCAN_STR(in_ip), &in_port);
			if (rs < 10) {
				log(ERROR, "wrong format for dnat-rules");
				continue;
			}
			struct dnat_rule * rule = malloc(sizeof(struct dnat_rule));
			rule->external_ip = out_ip;
			rule->internal_ip = in_ip;
			rule->external_port = out_port;
			rule->internal_port = in_port;
			list_add_tail(&rule->list, &nat.rules);
			printf("dnat-rules: " IP_FMT ":%hu -> " IP_FMT ":%hu\n", 
					HOST_IP_FMT_STR(out_ip), out_port, HOST_IP_FMT_STR(in_ip), in_port);
		} else {
			log(DEBUG, "%s", buff);
		}
	}

	return 0;
}

// initialize
void nat_init(const char *config_file)
{
	memset(&nat, 0, sizeof(nat));

	for (int i = 0; i < HASH_8BITS; i++)
		init_list_head(&nat.nat_mapping_list[i]);

	init_list_head(&nat.rules);

	// seems unnecessary
	memset(nat.assigned_ports, 0, sizeof(nat.assigned_ports));

	parse_config(config_file);

	pthread_mutex_init(&nat.lock, NULL);

	pthread_create(&nat.thread, NULL, nat_timeout, NULL);
}

void nat_exit()
{
	fprintf(stdout, "TODO: release all resources allocated.\n");
	pthread_mutex_lock(&nat.lock);

	for (int i = 0; i < HASH_8BITS; i++) {
		struct nat_mapping * entry = NULL, * entry_q = NULL;
		list_for_each_entry_safe(entry, entry_q, &nat.nat_mapping_list[i], list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}

	pthread_kill(nat.thread, SIGTERM);
	pthread_mutex_unlock(&nat.lock);
}
