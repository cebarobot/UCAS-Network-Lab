#ifndef __IP_H__
#define __IP_H__

#include <stdint.h>

#define IP_FMT	"%hhu.%hhu.%hhu.%hhu"
#define IP_FMT_STR(ip)  ((uint8_t *)&(ip))[3], \
						((uint8_t *)&(ip))[2], \
 						((uint8_t *)&(ip))[1], \
					    ((uint8_t *)&(ip))[0]

#define IP_SCAN_STR(ip) ((uint8_t *)&(ip) + 3), \
						((uint8_t *)&(ip) + 2), \
 						((uint8_t *)&(ip) + 1), \
					    ((uint8_t *)&(ip) + 0)

#endif