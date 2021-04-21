#include "base.h"
#include <stdio.h>

extern ustack_t *instance;

void broadcast_packet(iface_info_t *iface, const char *packet, int len)
{
	// broadcast packet 
	iface_info_t * one_iface;
	list_for_each_entry(one_iface, &instance->iface_list, list) {
		if (one_iface->index != iface->index) {
			iface_send_packet(one_iface, packet, len);
		}
	}
}
