/* SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later */

#include <stdarg.h>
#include <string.h>
#include <stdlib.h>

#include "libmctp.h"
#include "libmctp-log.h"
#include "libmctp-cmds.h"

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef MCTP_HAVE_STDIO
#include <stdio.h>
#endif

#ifdef MCTP_HAVE_SYSLOG
#include <syslog.h>
#endif

#include "utils.h"

static const char *eidPath = "/usr/share/mctp/eid.cfg";

/*identify the str start with a specific str or not*/
static int startWith(const char *str, const char *c)
{
	int len = strlen(c);
	int i;

	for ( i=0; i<len; i++ )
	{
		if ( str[i] != c[i] )
		{
			return 0;
		}
	}

	return 1;
}

int parseEIDConfig(struct eid_routing_entry *p)
{
	const char TAG_COMMENT[] = "#";

	FILE *fd = NULL;
	int buffSize = 120;
	char tmp_buf[buffSize];
	char t[5], q[5];
	int i = 0;
	int ret;

	fd = fopen(eidPath, "r");
	if (NULL == fd) {
		mctp_prerr("Cannot Open File %s!\n", eidPath);
		return -1;
	}
	mctp_prdebug("%s \n", __func__);
	while( NULL != fgets(tmp_buf, buffSize, fd) )
	{
		mctp_prdebug("%s \n", tmp_buf);
		if (!startWith(tmp_buf, TAG_COMMENT))
		{
			ret = sscanf(tmp_buf, "%s %s\n", t, q);
			if (ret == 2) {
				/* TODO: Config file should has all information
				 * EID range, phy range, transport type,..
				 * as Table 27 in DSP0236 */
				p[i].addr[0] = strtoul(t, NULL, 16);;
				p[i].eid[0] = strtoul(q, NULL, 10);
				p[i].eid_range_size = 1;
				p[i].phys_address_size = 1;
				SET_ENDPOINT_TYPE(p[i].entry_type, MCTP_SIMPLE_ENDPOINT);
				SET_ENDPOINT_ID_TYPE(p[i].entry_type, MCTP_STATIC_EID);
				SET_ROUTING_ENTRY_PORT(p[i].entry_type, 0);
				p[i].phys_transport_binding_id = MCTP_BINDING_SMBUS;
				p[i].phys_media_type_id = MCTP_SMBUS30_I2C1MHZ_COMPATIBLE;
				p[i].starting_eid = p[i].eid[0];
			}
			i++;
		}
	}

	return 0;

}
