#include "mospf_database.h"
#include "mospf_nbr.h"
#include "base.h"
#include "list.h"
#include "ip.h"
#include "rtable.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>

#define BIG_INT 0x3f3f3f3f

static u32 * rid_map;
static mospf_db_entry_t ** rid_db_map;
static int rid_map_cnt;

static int ** graph;
static int source;

static int * dist;
static int * visited;
static int * prev;

void init_rid_map() {
    rid_map = malloc(sizeof(u32) * mospf_db_cnt);
    rid_db_map = malloc(sizeof(mospf_db_entry_t *) * mospf_db_cnt);

    mospf_db_entry_t * db_p = NULL;
    rid_map_cnt = 0;
    list_for_each_entry(db_p, &mospf_db, list) {
        rid_map[rid_map_cnt] = db_p->rid;
        rid_db_map[rid_map_cnt] = db_p;
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

void free_rid_map() {
    free(rid_map);
}

void print_rid_map() {
    printf("------print rid map\n");
    for (int i = 0; i < rid_map_cnt; i++) {
        printf("%d " IP_FMT "\n", i, HOST_IP_FMT_STR(rid_map[i]));
    }
}

void init_abstract_graph() {
    graph = (int **) malloc(sizeof(int *) * rid_map_cnt);
    for (int i = 0; i < rid_map_cnt; i++) {
        graph[i] = (int *) malloc(sizeof(int) * rid_map_cnt);
        memset(graph[i], 0x3f, sizeof(int) * rid_map_cnt);
    }

    dist = malloc(sizeof(int) * rid_map_cnt);
    visited = malloc(sizeof(int) * rid_map_cnt);
    prev = malloc(sizeof(int) * rid_map_cnt);

    mospf_db_entry_t * db_p = NULL;
    int db_i = 0;
    list_for_each_entry(db_p, &mospf_db, list) {
        for (int j = 0; j < db_p->nadv; j++) {
            int db_j = find_rid_map(db_p->array[j].rid);
            // printf("[[[[[[[[[%d, %d\n", db_i, db_j);
            if (db_j >= 0) {
                graph[db_i][db_j] = 1;
            }
        }
        db_i += 1;
    }
}

void free_abstract_graph() {
    for (int i = 0; i < rid_map_cnt; i++) {
        free(graph[i]);
    }
    free(graph);

    free(dist);
    free(visited);
    free(prev);
}

void print_abstract_graph() {
    printf("------print abstract graph\n");
    for (int i = 0; i < rid_map_cnt; i++) {
        for (int j = 0; j < rid_map_cnt; j++) {
            printf("%d, ", graph[i][j]);
        }
        printf("\n");
    }
}

int find_min_dist(int * dist, int * visited, int cond, int size) {
    int min_dist = BIG_INT;
    int min_id = -1;
    for (int i = 0; i < size; i++) {
        if (visited[i] == cond && dist[i] < min_dist) {
            min_dist = dist[i];
            min_id = i;
        }
    }
    return min_id;
}

void dijkstra(int source, int size, int ** graph, int * dist, int * visited, int * prev) {
    for (int i = 0; i < size; i++) {
        dist[i] = BIG_INT;
        visited[i] = 0;
        prev[i] = -1;
    }
    dist[source] = 0;

    for (int i = 0; i < size; i++) {
        int u = find_min_dist(dist, visited, 0, size);
        if (u < 0) {
            break;
        }
        visited[u] = 1;
        for (int v = 0; v < size; v++) {
            printf("working dijkstra at i%d u%d v%d\n", i, u, v);
            if (!visited[v] && dist[u] + graph[u][v] < dist[v]) {
                dist[v] = dist[u] + graph[u][v];
                prev[v] = u;
            }
        }
    }

    printf("dist:\t");
    for (int i = 0; i < size; i++) {
        printf("%d\t", dist[i]);
    }
    printf("\n");
    printf("prev:\t");
    for (int i = 0; i < size; i++) {
        printf("%d\t", prev[i]);
    }
    printf("\n");
    printf("vis: \t");
    for (int i = 0; i < size; i++) {
        printf("%d\t", visited[i]);
    }
    printf("\n");
}

int get_first_hop(int u) {
    while (u >= 0 && dist[u] > 1) {
        u = prev[u];
    }
    return u;
}

u32 get_ip_iface_of_nbr(u32 rid, iface_info_t ** iface_match) {
    iface_info_t * iface_p = NULL;
    list_for_each_entry(iface_p, &instance->iface_list, list) {
        mospf_nbr_t * nbr_p = NULL;
        list_for_each_entry(nbr_p, &iface_p->nbr_list, list) {
            if (rid == nbr_p->nbr_id) {
                *iface_match = iface_p;
                return nbr_p->nbr_ip;
            }
        }
    }
    return 0;
}

void set_rtable_with_path() {
    while(1) {
        int dst = find_min_dist(dist, visited, 1, rid_map_cnt);
        printf("dst: %d\n", dst);
        if (dst < 0) {
            break;
        }
        visited[dst] = 0;
        if (dst == source) {
            continue;
        }
        u32 dst_rid = rid_map[dst];
        mospf_db_entry_t * db_entry = rid_db_map[dst];

        printf("dst: %d - " IP_FMT "\n", dst, HOST_IP_FMT_STR(dst_rid));

        // get first hop
        int hop = get_first_hop(dst);
        u32 hop_rid = rid_map[hop];

        if (hop == 0) {
            printf("error: cannot find first hop\n");
            continue;
        }

        // get gw & iface
        iface_info_t * hop_iface;
        u32 hop_ip = get_ip_iface_of_nbr(hop_rid, &hop_iface);

        for (int i = 0; i < db_entry->nadv; i++) {
            struct mospf_lsa * this_lsa = db_entry->array + i;
            printf("net: " IP_FMT "\n", HOST_IP_FMT_STR(this_lsa->network));
            try_add_new_rt_entry(this_lsa->network, this_lsa->mask, hop_ip, hop_iface);
        }
    }

}

void update_rtable_from_database() {
    init_rid_map();

    source = find_rid_map(instance->router_id);
    if (source < 0) {
        printf("source node is not in database\n");
        free_rid_map();
        return;
    }

    init_abstract_graph();

    print_rid_map();
    print_abstract_graph();
    
    dijkstra(source, rid_map_cnt, graph, dist, visited, prev);

    pthread_mutex_lock(&rtable_lock);

    clear_rtable();
    load_rtable_from_kernel();

    set_rtable_with_path();
    
    print_rtable();

    pthread_mutex_unlock(&rtable_lock);

    free_abstract_graph();
    free_rid_map();
}