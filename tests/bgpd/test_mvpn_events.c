// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2026 Blockcast, Inc.
 */

#include <zebra.h>

#include "memory.h"
#include "buffer.h"
#include "privs.h"

#include "bgpd/bgp_mvpn_events.h"

struct zebra_privs_t bgpd_privs = {};

static void test_draining_subscriber_uses_live_backlog(void)
{
	struct buffer *wb = buffer_new(0);
	char *payload = XCALLOC(MTYPE_TMP, 64 * 1024);
	char drain[4096];
	size_t total = 0;
	int sockets[2];
	int sndbuf = 4096;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	assert(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &sndbuf,
			  sizeof(sndbuf)) == 0);
	assert(fcntl(sockets[0], F_SETFL,
		     fcntl(sockets[0], F_GETFL) | O_NONBLOCK) == 0);

	for (size_t queued = 0; queued < BGP_MVPN_EVENT_SINK_MAX_BACKLOG;
	     queued += 64 * 1024)
		buffer_put(wb, payload, 64 * 1024);
	assert(buffer_pending(wb) == BGP_MVPN_EVENT_SINK_MAX_BACKLOG);
	assert(!bgp_mvpn_event_backlog_exceeded(wb, 0));
	assert(bgp_mvpn_event_backlog_exceeded(wb, 1));
	buffer_reset(wb);

	while (total <= BGP_MVPN_EVENT_SINK_MAX_BACKLOG) {
		buffer_status_t status;

		assert(!bgp_mvpn_event_backlog_exceeded(wb, 64 * 1024));
		status = buffer_write(wb, sockets[0], payload, 64 * 1024);
		assert(status == BUFFER_PENDING);
		total += 64 * 1024;

		while (buffer_pending(wb) > 0) {
			assert(read(sockets[1], drain, sizeof(drain)) > 0);
			status = buffer_flush_available(wb, sockets[0]);
			assert(status != BUFFER_ERROR);
		}
	}

	assert(total > BGP_MVPN_EVENT_SINK_MAX_BACKLOG);
	assert(buffer_pending(wb) == 0);
	assert(!bgp_mvpn_event_backlog_exceeded(wb, 1));

	close(sockets[0]);
	close(sockets[1]);
	XFREE(MTYPE_TMP, payload);
	buffer_free(wb);
}

int main(void)
{
	test_draining_subscriber_uses_live_backlog();
	return 0;
}
