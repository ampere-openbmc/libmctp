/* SPDX-License-Identifier: Apache-2.0 */

#ifndef _LIBMCTP_SMBUS_H
#define _LIBMCTP_SMBUS_H

#ifdef __cplusplus
extern "C" {
#endif

#include "libmctp.h"
#include <poll.h>

struct mctp_binding_smbus;

struct mctp_binding *mctp_binding_smbus_core(struct mctp_binding_smbus *b);
void mctp_smbus_destroy(struct mctp_binding_smbus *smbus);
struct mctp_binding_smbus *mctp_smbus_init(uint8_t addr);

/* direct function call IO */
typedef int (*mctp_smbus_tx_fn)(const void *data, uint8_t *buf, uint32_t len)
	__attribute__((warn_unused_result));

#ifdef MCTP_HAVE_FILEIO

int mctp_smbus_open_fd(struct mctp_binding_smbus *smbus,
		       uint8_t bus, uint8_t in_addr);
int mctp_smbus_read(struct mctp_binding_smbus *smbus);
struct pollfd;
int mctp_smbus_init_pollfd(struct mctp_binding_smbus *smbus,
			   struct pollfd *pollfd);
int mctp_smbus_get_out_fd(struct mctp_binding_smbus *smbus);
int mctp_smbus_get_in_fd(struct mctp_binding_smbus *smbus);
void mctp_smbus_set_in_fd(struct mctp_binding_smbus *smbus, int fd);
void mctp_smbus_set_out_fd(struct mctp_binding_smbus *smbus, int fd);
void mctp_smbus_scan_process(struct mctp_binding_smbus *smbus);

#endif

#ifdef __cplusplus
}
#endif
#endif /* _LIBMCTP_SMBUS_H */
