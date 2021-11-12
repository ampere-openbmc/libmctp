
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#ifdef MCTP_HAVE_FILEIO
#include <fcntl.h>
#endif

#include <linux/i2c-dev.h>
#include <linux/i2c.h>
#include <sys/ioctl.h>
#include "container_of.h"

#include "libmctp-alloc.h"
#include "libmctp-log.h"
#include "libmctp-smbus.h"
#include "libmctp.h"
#include "utils.h"

#define binding_to_smbus(b) \
	container_of(b, struct mctp_binding_smbus, binding)

#define MCTP_SMBUS_COMMAND_CODE		0x0f
#define SMBUS_PEC_SIZE			1

struct mctp_binding_smbus {
	struct mctp_binding binding;
#ifdef MCTP_HAVE_FILEIO
	int out_fd;
	int in_fd;
#endif
	struct eid_routing_entry routing_table[EID_ROUTING_TABLE_SIZE];
	uint8_t src_addr;
	mctp_smbus_tx_fn tx_fn;
	const void *tx_fn_data;
};

struct mctp_smbus_hdr {
	uint8_t dest;
	uint8_t	command;
	uint8_t byte_count;
	uint8_t	src;
} __attribute__((packed));

#define POLY			(0x1070U << 3)
static uint8_t crc8(uint16_t data)
{
	int i;

	for (i = 0; i < 8; i++) {
		if (data & 0x8000)
			data = data ^ POLY;
		data = data << 1;
	}
	return (uint8_t)(data >> 8);
}

/**
 * i2c_smbus_pec - Incremental CRC8 over the given input data array
 * @crc: previous return crc8 value
 * @p: pointer to data buffer.
 * @count: number of bytes in data buffer.
 *
 * Incremental CRC8 over count bytes in the array pointed to by p
 */
static uint8_t i2c_smbus_pec(uint8_t crc, uint8_t *p, size_t count)
{
	int i;

	for (i = 0; i < count; i++)
		crc = crc8((crc ^ p[i]) << 8);
	return crc;
}

static uint8_t cal_pec(uint8_t *data, uint8_t len)
{
	uint8_t pec = 0;

	pec = i2c_smbus_pec(pec, data, len);

	return pec;
}

static void add_routing_table(struct mctp_binding_smbus *smbus, uint8_t eid, uint8_t addr)
{
	int i;
	struct eid_routing_entry *entry;

	mctp_prdebug("Add Routing Table: addr=%x, eid=%d\n", addr, eid);
	for(i = 0; i< EID_ROUTING_TABLE_SIZE; i++) {
		entry = &smbus->routing_table[i];
		/* TODO: Only support one EID and one phy address
		 * For EID range and phy address range, consider change here. */
		entry->eid_range_size = 1;
		entry->phys_address_size = 1;
		if (entry->eid[0] == 0) {
			entry->eid[0] = eid;
			entry->addr[0] = addr;
			return;
		} else if (entry->eid[0] == eid) {
			entry->addr[0] = addr;
			return;
		}
	}
	mctp_prerr("EID routing table is full\n");
}

static uint8_t find_addr_in_table(struct mctp_binding_smbus *smbus, uint8_t eid)
{
	int i;
	struct eid_routing_entry *entry;

	for(i = 0; i< EID_ROUTING_TABLE_SIZE; i++) {
		entry = &smbus->routing_table[i];
		/* TODO: Only support one EID and one phy address
		 * For EID range and phy address range, consider change here. */
		if (entry->eid[0] == eid)
			return entry->addr[0];
	}
	mctp_prerr("EID does not exist in routing table\n");
	return 0xFF;
}


static int mctp_smbus_rx(struct mctp_binding_smbus *smbus, uint8_t *buf, uint32_t len)
{
	struct mctp_smbus_hdr *smbus_hdr;
	struct mctp_pktbuf *pkt;
	struct mctp_hdr *hdr;
	uint8_t pec;

	if (len < sizeof(struct mctp_smbus_hdr) + SMBUS_PEC_SIZE) {
		/* This condition hits from from time to time, even with
		 * a properly written poll loop, although it's not clear
		 * why. Return so that the upper layer can retry.
		 */
		return 1;
	}
	mctp_prdebug("%s received %d bytes\n", __func__, len);

	pec = cal_pec(buf, len-1);
	if(pec != buf[len-1]) {
		mctp_prerr("Invalid PEC(expected=0x%02x, pec=0x%02x )\n", pec, buf[len-1]);
		return -1;
	}

	smbus_hdr = (struct mctp_smbus_hdr *)buf;
	if (smbus_hdr->byte_count != (len - sizeof(*smbus_hdr))) {
		mctp_prerr("Invalid smbus payload sized %d, expecting %d",
			    smbus_hdr->byte_count, len - sizeof(*smbus_hdr));
		return -1;
	}

	if(smbus_hdr->command != MCTP_SMBUS_COMMAND_CODE) {
		mctp_prerr("Invalid command code %d", smbus_hdr->command);
		return -1;
	}

	pkt = mctp_pktbuf_alloc(&smbus->binding, smbus_hdr->byte_count - 1);
	if(!pkt) {
		mctp_prerr("Out of memory when allocating pktbuf\n");
		return -1;
	}
	memcpy(pkt->data, buf, len);
	hdr = mctp_pktbuf_hdr(pkt);
	add_routing_table(smbus, hdr->src, smbus_hdr->src >> 1);
	mctp_bus_rx(&smbus->binding, pkt);

	return 0;
}


static int mctp_binding_smbus_tx(struct mctp_binding *b,
		struct mctp_pktbuf *pkt)
{
	struct mctp_binding_smbus *smbus = binding_to_smbus(b);
	struct mctp_smbus_hdr *smbus_hdr;
	struct mctp_hdr *mctp_hdr = mctp_pktbuf_hdr(pkt);
	uint8_t len = mctp_pktbuf_size(pkt);
	uint8_t src_addr, dest_addr;
	uint8_t *pec;

	mctp_prdebug("%s \n", __func__);
	smbus_hdr = (struct mctp_smbus_hdr*)pkt->data;
	src_addr = find_addr_in_table(smbus, mctp_hdr->src);
	dest_addr = find_addr_in_table(smbus, mctp_hdr->dest);
	if (dest_addr == 0xFF)
		return -1;

	smbus_hdr->dest = (dest_addr << 1) & 0xfe;
	smbus_hdr->command = MCTP_SMBUS_COMMAND_CODE;
	smbus_hdr->byte_count = len + sizeof(smbus_hdr->src);
	smbus_hdr->src = smbus->src_addr << 1 | 0x01;

	len += sizeof(struct mctp_smbus_hdr);
	pec = pkt->data + len; // find the offset of PEC
	*pec = cal_pec(pkt->data, len);
	len++;

	if(!smbus->tx_fn) {
		mctp_prdebug("%s tx_fn is null\n", __func__);
		return 0;
	}
	return smbus->tx_fn(smbus->tx_fn_data, pkt->data, len);
}

static int mctp_binding_smbus_start(struct mctp_binding *binding)
{
	struct mctp_binding_smbus *smbus = binding_to_smbus(binding);
	int i;
	uint8_t eid, addr;

	mctp_prdebug("%s \n", __func__);
	/* Parse EID config file and store to routing table. */
	if (parseEIDConfig(&(smbus->routing_table[0])) < 0)
	{
		mctp_prdebug("Parse eid.cfg failed \n");
		return -1;
	}

	mctp_binding_set_tx_enabled(binding, true);

	return 0;
}

struct mctp_binding *mctp_binding_smbus_core(struct mctp_binding_smbus *b)
{
	return &b->binding;
}

static void mctp_smbus_set_tx_fn(struct mctp_binding_smbus* smbus, mctp_smbus_tx_fn fn, const void *data)
{
	mctp_prdebug("%s \n", __func__);
	smbus->tx_fn = fn;
	smbus->tx_fn_data = data;
}

static void mctp_smbus_get_routing_table(struct mctp_binding *binding,
					 struct eid_routing_entry **table)
{
	mctp_prdebug("%s \n", __func__);
	struct mctp_binding_smbus *smbus = binding_to_smbus(binding);

	*table = &smbus->routing_table[0];
}

struct mctp_binding_smbus *mctp_smbus_init(uint8_t addr)
{
	struct mctp_binding_smbus *smbus;

	smbus = __mctp_alloc(sizeof(*smbus));
	memset(smbus, 0, sizeof(*smbus));
#ifdef MCTP_HAVE_FILEIO
	smbus->in_fd = -1;
	smbus->out_fd = -1;
#endif

	smbus->binding.name = "smbus";
	smbus->binding.version = 1;
	smbus->binding.pkt_size = MCTP_PACKET_SIZE(MCTP_BTU);
	smbus->binding.pkt_header = 4; // dest_addr, cmd, byte count, src_addr
	smbus->binding.pkt_trailer = 1; //pec
	smbus->src_addr =  addr;

	smbus->binding.tx = mctp_binding_smbus_tx;
	smbus->binding.start = mctp_binding_smbus_start;
	smbus->binding.get_routing_table = mctp_smbus_get_routing_table;
#if 0
	mctp_set_log_stdio(MCTP_LOG_DEBUG);
#endif
	return smbus;
}

void mctp_smbus_destroy(struct mctp_binding_smbus *smbus)
{
	__mctp_free(smbus);
}

#ifdef MCTP_HAVE_FILEIO
int mctp_smbus_read(struct mctp_binding_smbus *smbus)
{
	uint8_t buf[256];
	int ret;
	ssize_t len;
	ret = lseek(smbus->in_fd, 0, SEEK_SET);
	if (ret < 0) {
		mctp_prerr("Failed to seek");
		return -1;
	}

	len = read(smbus->in_fd, buf, sizeof(buf));
	if (len < 0) {
		mctp_prerr("Failed to read");
		return -1;
	}

	return mctp_smbus_rx(smbus, buf, len);
}

static int mctp_smbus_write(const void *fn_data, uint8_t *buf, uint32_t len)
{
	uint8_t *tx_buf = (uint8_t *)buf;
	struct mctp_binding_smbus *smbus = (struct mctp_binding_smbus *)fn_data;
	struct i2c_msg msg;
	struct i2c_rdwr_ioctl_data data = {&msg, 1};
	int ret;

#if 0
	mctp_prdebug("%s xfer %d bytes to addr 0x%02x\n data:", __func__, len, tx_buf[0]);
	for(int i=1; i<len;i++) {
		mctp_prdebug("0x%02x ", tx_buf[i]);
	}
#endif

	msg.addr = tx_buf[0]>>1;
	msg.flags = 0;
	msg.len = len - 1;
	msg.buf = tx_buf + 1;

	ret = ioctl(smbus->out_fd, I2C_RDWR, &data);
	if (ret <0 ) {
		mctp_prdebug("%s: ioctl ret = %d", __func__, ret);
		return ret;
	}
	return 0;
}

static int mctp_smbus_open_in_fd(struct mctp_binding_smbus *smbus, uint8_t bus, uint8_t addr)
{
	uint8_t path[256];
	char slave_mqueue[20];
	size_t mqueue_size = 0;
	size_t size = 0;
	int fd = 0;

	snprintf(path, sizeof(path), "/sys/bus/i2c/devices/%d-%04x/slave-mqueue",
		 bus, addr);
	mctp_prdebug("open %s\n", path);
	smbus->in_fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (smbus->in_fd < 0) {
		mctp_prdebug("cannot open %s\n", path);
		return -1;
	}

#if 0
	// Device doesn't exist.  Create it.
	mctp_prdebug("Device %s doesn't exist.  Create it.n", path);
	snprintf(path, sizeof(path), "/sys/bus/i2c/devices/i2c-%d/new_device", bus);
	path[sizeof(path) - 1] = '\0';
	fd = open(path, O_WRONLY);
	if (fd < 0) {
		mctp_prerr("can't open root device %s: %m", path);
		return -1;
	}

	mqueue_size = sizeof(slave_mqueue);
	snprintf(slave_mqueue, mqueue_size, "slave-mqueue %#04x", addr);

	size = write(fd, slave_mqueue, mqueue_size);
	close(fd);
	if (size != mqueue_size) {
		mctp_prerr("can't create mqueue device on %s: %m", path);
		return -1;
	}

	snprintf(path, sizeof(path), "/sys/bus/i2c/devices/%d-%04x/slave-mqueue",
		 bus, addr);
	smbus->in_fd = open(path, O_RDONLY | O_NONBLOCK | O_CLOEXEC);
	if (smbus->in_fd < 0) {
		mctp_prdebug("cannot open %s\n", path);
		return -1;
	}
#endif

	return 0;
}

static int mctp_smbus_open_out_fd(struct mctp_binding_smbus *smbus, uint8_t bus)
{
	uint8_t path[256];

	snprintf(path, sizeof(path), "/dev/i2c-%d", bus);
	mctp_prdebug("open %s\n", path);
	smbus->out_fd = open(path, O_RDWR);
	if (smbus->out_fd < 0) {
		mctp_prdebug("cannot open %s\n", path);
		return -1;
	}

	mctp_smbus_set_tx_fn(smbus, mctp_smbus_write, smbus);

	return 0;
}

int mctp_smbus_open_fd(struct mctp_binding_smbus *smbus,
		       uint8_t bus, uint8_t in_addr)
{
	int ret = 0;

	ret += mctp_smbus_open_out_fd(smbus, bus);
	ret += mctp_smbus_open_in_fd(smbus, bus, in_addr);

	if (ret < 0)
		return -1;

	return 0;
}

int mctp_smbus_init_pollfd(struct mctp_binding_smbus *smbus,
			   struct pollfd *pollfd)
{
	pollfd->fd = smbus->in_fd;
	pollfd->events = POLLIN;
}

int mctp_smbus_get_in_fd(struct mctp_binding_smbus *smbus)
{
	return smbus->in_fd;
}

int mctp_smbus_get_out_fd(struct mctp_binding_smbus *smbus)
{
	return smbus->out_fd;
}

void mctp_smbus_set_in_fd(struct mctp_binding_smbus *smbus, int fd)
{
	smbus->in_fd = fd;
}

void mctp_smbus_set_out_fd(struct mctp_binding_smbus *smbus, int fd)
{
	smbus->out_fd = fd;
}

void mctp_smbus_scan_process(struct mctp_binding_smbus *smbus)
{
	struct i2c_msg msg;
	struct i2c_rdwr_ioctl_data data = {&msg, 1};
	int i, ret;
	uint8_t tbuf = 0;
	struct eid_routing_entry *entry;

	for(i = 0; i< EID_ROUTING_TABLE_SIZE; i++) {
		entry = &smbus->routing_table[i];
		if (entry->addr[0]) {
			mctp_prdebug("Scan %x \n", entry->addr[0]);
			msg.addr = entry->addr[0];
			msg.flags = 0;
			msg.len = 1;
			msg.buf = &tbuf;
			ret = ioctl(smbus->out_fd, I2C_RDWR, &data);
			mctp_prdebug("Ret %d \n", ret);
			if (ret < 0) {
				/* Device not present */
				entry->state = UNUSED;
			} else {
				/* Device present */
				if (entry->state == UNUSED) {
					/* Call SetEID command*/
					entry->state = NEW;
				} else if (entry->state == NEW) {
					entry->state = ASSIGNED;
				}
			}
		}
	}
}
#endif
