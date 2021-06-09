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
	// TODO:
	fprintf(stdout, "TODO: determine the direction of this packet.\n");

	return DIR_INVALID;
}

// do translation for the packet: replace the ip/port, recalculate ip & tcp
// checksum, update the statistics of the tcp connection
void do_translation(iface_info_t *iface, char *packet, int len, int dir)
{
	// TODO:
	fprintf(stdout, "TODO: do translation for this packet.\n");
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
	}

	return NULL;
}

int parse_config(const char *filename)
{
	// TODO:
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
	// TODO:
	fprintf(stdout, "TODO: release all resources allocated.\n");
}
