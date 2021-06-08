#include "mospf_database.h"
#include "base.h"
#include "list.h"
#include "ip.h"
#include <stdlib.h>
#include <stdio.h>

static u32 * rid_map;
static int rid_map_cnt;

static int ** graph;

void init_rid_map() {
    rid_map = malloc(sizeof(u32) * mospf_db_cnt);

    mospf_db_entry_t * db_p = NULL;
    rid_map_cnt = 0;
    list_for_each_entry(db_p, &mospf_db, list) {
        rid_map[rid_map_cnt] = db_p->rid;
        rid_map_cnt += 1;
    }
}

int find_rid_map(u32 rid) {
    for (int i = 0; i < rid_map_cnt; i++) {
        if (rid_map[i] == rid) {
            return i;
        }
    }
    return -1;
}

void init_abstract_graph() {
    graph = malloc(sizeof(int *) * rid_map_cnt);
    for (int i = 0; i < rid_map_cnt; i++) {
        graph[i] = malloc(sizeof(int *) * rid_map_cnt);
    }

    mospf_db_entry_t * db_p = NULL;
    int db_i = 0;
    list_for_each_entry(db_p, &mospf_db, list) {
        for (int j = 0; j < db_p->nadv; j++) {
            int db_j = find_rid_map(db_p->array[j].rid);
            graph[db_i][db_j] = 1;
        }
        db_i += 1;
    }

}


void mospf_shortest_path() {
    init_rid_map();
    init_abstract_graph();

    printf("------print rid map\n");
    for (int i = 0; i < rid_map_cnt; i++) {
        printf("%d " IP_FMT "\n", i, HOST_IP_FMT_STR(rid_map[i]));
    }
    printf("------print abstract graph\n");

    for (int i = 0; i < rid_map_cnt; i++) {
        for (int j = 0; j < rid_map_cnt; j++) {
            printf("%d, ", graph[i][j]);
        }
        printf("\n");
    }

    free(rid_map);
}



void update_rtable_from_database() {
    // calculate shortest path
    mospf_shortest_path();

    // convert shortest path to route table

}