#ifndef __MOSPF_DATABASE_H__
#define __MOSPF_DATABASE_H__

#include "base.h"
#include "list.h"

#include "mospf_proto.h"

extern struct list_head mospf_db;
extern int mospf_db_cnt;

typedef struct {
	struct list_head list;
	u32	rid;
	u16	seq;
	int nadv;
	int alive;
	struct mospf_lsa *array;
} mospf_db_entry_t;

void init_mospf_db();
int aging_mospf_db();
int update_mospf_db(const char * mospf_lsu_msg);
void print_mospf_db();

#endif
