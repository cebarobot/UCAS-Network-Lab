#include "mospf_database.h"
#include "mospf_proto.h"
#include "ip.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

struct list_head mospf_db;

void init_mospf_db()
{
	init_list_head(&mospf_db);
}

int aging_mospf_db() {
	int db_changed = 0;

	mospf_db_entry_t * db_p = NULL, * db_q = NULL;
	list_for_each_entry_safe(db_p, db_q, &mospf_db, list) {
		db_p->alive -= 1;
		if (db_p->alive <= 0) {
			list_delete_entry(&db_p->list);
			free(db_p->array);
			free(db_p);
			db_changed = 1;
		}
	}

	return db_changed;
}

int update_mospf_db(const char * mospf_lsu_msg) {
	struct mospf_hdr * hdr = (void *) mospf_lsu_msg;
	struct mospf_lsu * lsu = (void *) (mospf_lsu_msg + MOSPF_HDR_SIZE);
	struct mospf_lsa * lsa_arr = (void *) (mospf_lsu_msg + MOSPF_HDR_SIZE + MOSPF_LSU_SIZE);

	u32 mospf_rid = ntohl(hdr->rid);
	u16 mospf_seq = ntohs(lsu->seq);
	u32 mospf_nadv = ntohl(lsu->nadv);

	mospf_db_entry_t * db_p = NULL, * db_match = NULL;
	list_for_each_entry(db_p, &mospf_db, list) {
		if (db_p->rid == mospf_rid) {
			db_match = db_p;
			break;
		}
	}

	if (!db_match) {
		db_match = malloc(sizeof(mospf_db_entry_t));
		list_add_tail(&db_match->list, &mospf_db);
		db_match->rid = mospf_rid;
	} else if (mospf_seq > db_match->seq) {
		if (db_match->array) {
			free(db_match->array);
		}
	} else {
		printf("no need to update db: %d, %d\n", mospf_seq, db_match->seq);
		// no need to update
		return 0;
	}

	db_match->seq = mospf_seq;
	db_match->alive = MOSPF_DATABASE_TIMEOUT;
	db_match->nadv = mospf_nadv;

	int array_size = mospf_nadv * MOSPF_LSA_SIZE;
	db_match->array = malloc(array_size);
	for (int i = 0; i < mospf_nadv; i++) {
		db_match->array[i].mask = ntohl(lsa_arr[i].mask);
		db_match->array[i].network = ntohl(lsa_arr[i].network);
		db_match->array[i].rid = ntohl(lsa_arr[i].rid);
	}
	return 1;
}

void print_mospf_db() {
	
	printf("+++++++++++++++++++++++++++ MOSPF DB +++++++++++++++++++++++++++\n");

	mospf_db_entry_t * db_p = NULL;
	list_for_each_entry(db_p, &mospf_db, list) {
		printf("router: " IP_FMT ", seq: %d, alive: %d\n", HOST_IP_FMT_STR(db_p->rid), db_p->seq, db_p->alive);
		for (int i = 0; i < db_p->nadv; i++) {
			printf("\tnbr "IP_FMT ":\t", HOST_IP_FMT_STR(db_p->array[i].rid));
			printf(IP_FMT ",\t", HOST_IP_FMT_STR(db_p->array[i].network));
			printf(IP_FMT "\n", HOST_IP_FMT_STR(db_p->array[i].mask));
		}
	}
	printf("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++\n");
}