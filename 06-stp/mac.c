#include "mac.h"
#include "log.h"

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

mac_port_map_t mac_port_map;

// initialize mac_port table
void init_mac_port_table()
{
	bzero(&mac_port_map, sizeof(mac_port_map_t));

	for (int i = 0; i < HASH_8BITS; i++) {
		init_list_head(&mac_port_map.hash_table[i]);
	}

	pthread_mutex_init(&mac_port_map.lock, NULL);

	pthread_create(&mac_port_map.thread, NULL, sweeping_mac_port_thread, NULL);
}

// destroy mac_port table
void destory_mac_port_table()
{
	pthread_mutex_lock(&mac_port_map.lock);
	mac_port_entry_t *entry, *q;
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(entry, q, &mac_port_map.hash_table[i], list) {
			list_delete_entry(&entry->list);
			free(entry);
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
}

// lookup the mac address in mac_port table
iface_info_t *lookup_port(u8 mac[ETH_ALEN])
{
	// implement the lookup process here
	mac_port_entry_t * one_entry = NULL;
	u8 mac_hash = hash8((void *) mac, ETH_ALEN);
	// log(DEBUG, "mac_hash = %d", mac_hash);

	pthread_mutex_lock(&mac_port_map.lock);
	// log(DEBUG, "list head = %p", (&mac_port_map.hash_table[mac_hash])->next);
	// log(DEBUG, "initial = %p", list_entry((&mac_port_map.hash_table[mac_hash])->next, mac_port_entry_t, list));
	list_for_each_entry(one_entry, &mac_port_map.hash_table[mac_hash], list) {
		// log(DEBUG, "one_entry = %p", one_entry);
		if (memcmp(one_entry->mac, mac, ETH_ALEN) == 0) {
			// log(DEBUG, "Found.");
			pthread_mutex_unlock(&mac_port_map.lock);
			return one_entry->iface;
		}
	}
	// log(DEBUG, "Not found.");
	pthread_mutex_unlock(&mac_port_map.lock);
	return NULL;
}

// insert the mac -> iface mapping into mac_port table
void insert_mac_port(u8 mac[ETH_ALEN], iface_info_t *iface)
{
	// implement the insertion process here
	mac_port_entry_t * one_entry = NULL;
	u8 mac_hash = hash8((void *) mac, ETH_ALEN);
	time_t now = time(NULL);

	pthread_mutex_lock(&mac_port_map.lock);

	list_for_each_entry(one_entry, &mac_port_map.hash_table[mac_hash], list) {
		if (memcmp(one_entry->mac, mac, ETH_ALEN) == 0) {
			// Found this mac
			one_entry->iface = iface;
			one_entry->visited = now;

			pthread_mutex_unlock(&mac_port_map.lock);
			return;
		}
	}

	// not found
	one_entry = malloc(sizeof(mac_port_entry_t));
	memcpy(one_entry->mac, mac, ETH_ALEN);
	one_entry->iface = iface;
	one_entry->visited = now;
	list_add_head(&one_entry->list, &mac_port_map.hash_table[mac_hash]);
	
	pthread_mutex_unlock(&mac_port_map.lock);
}

// dumping mac_port table
void dump_mac_port_table()
{
	mac_port_entry_t *entry = NULL;
	time_t now = time(NULL);

	fprintf(stdout, "dumping the mac_port table:\n");
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry(entry, &mac_port_map.hash_table[i], list) {
			fprintf(stdout, ETHER_STRING " -> %s, %d\n", ETHER_FMT(entry->mac),
					entry->iface->name, (int)(now - entry->visited));
		}
	}

	pthread_mutex_unlock(&mac_port_map.lock);
}

// sweeping mac_port table, remove the entry which has not been visited in the
// last 30 seconds.
int sweep_aged_mac_port_entry()
{
	// implement the sweeping process here
	mac_port_entry_t *one_entry = NULL;
	mac_port_entry_t *next_entry = NULL;
	time_t now = time(NULL);
	
	pthread_mutex_lock(&mac_port_map.lock);
	for (int i = 0; i < HASH_8BITS; i++) {
		list_for_each_entry_safe(one_entry, next_entry, &mac_port_map.hash_table[i], list) {
			if ((int)(now - one_entry->visited) > MAC_PORT_TIMEOUT) {
				log(DEBUG, "last visit = %ld", one_entry->visited);
				log(INFO, "Entry: " ETHER_STRING " -> %s are removed.", ETHER_FMT(one_entry->mac), 
						one_entry->iface->name);
				list_delete_entry(&one_entry->list);
				free(one_entry);
			}
		}
	}
	pthread_mutex_unlock(&mac_port_map.lock);
	return 0;
}

// sweeping mac_port table periodically, by calling sweep_aged_mac_port_entry
void *sweeping_mac_port_thread(void *nil)
{
	while (1) {
		sleep(1);
		log(DEBUG, "now = %ld", time(NULL));
		int n = sweep_aged_mac_port_entry();

		if (n > 0)
			log(DEBUG, "%d aged entries in mac_port table are removed.", n);
	}

	return NULL;
}
