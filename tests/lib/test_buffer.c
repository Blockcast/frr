// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2004 Paul Jakma
 */

#include <zebra.h>
#include <memory.h>
#include <lib_vty.h>
#include <buffer.h>

struct event_loop *master;

static void test_pending_tracks_partial_flush(void)
{
	struct buffer *b = buffer_new(1024);
	char *payload = XCALLOC(MTYPE_TMP, 1024 * 1024);
	char drain[4096];
	int sockets[2];
	int sndbuf = 4096;
	bool saw_partial_drain = false;
	buffer_status_t status;

	assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	assert(setsockopt(sockets[0], SOL_SOCKET, SO_SNDBUF, &sndbuf,
			  sizeof(sndbuf)) == 0);
	assert(fcntl(sockets[0], F_SETFL,
		     fcntl(sockets[0], F_GETFL) | O_NONBLOCK) == 0);

	status = buffer_write(b, sockets[0], payload, 1024 * 1024);
	assert(status == BUFFER_PENDING);
	while (buffer_pending(b) > 0) {
		size_t before = buffer_pending(b);
		size_t after;

		assert(read(sockets[1], drain, sizeof(drain)) > 0);
		status = buffer_flush_available(b, sockets[0]);
		assert(status != BUFFER_ERROR);
		after = buffer_pending(b);
		assert(after <= before);
		if (after > 0 && after < before)
			saw_partial_drain = true;
	}
	assert(saw_partial_drain);

	close(sockets[0]);
	close(sockets[1]);
	XFREE(MTYPE_TMP, payload);
	buffer_free(b);
}

int main(int argc, char **argv)
{
	struct buffer *b1, *b2;
	int n;
	char junk[3];
	char c = 'a';

	lib_cmd_init();
	test_pending_tracks_partial_flush();

	if ((argc != 2) || (sscanf(argv[1], "%d%1s", &n, junk) != 1)) {
		fprintf(stderr, "Usage: %s <number of chars to simulate>\n",
			*argv);
		return 1;
	}

	b1 = buffer_new(0);
	b2 = buffer_new(1024);
	assert(buffer_pending(b1) == 0);
	assert(buffer_pending(b2) == 0);

	while (n-- > 0) {
		buffer_put(b1, &c, 1);
		buffer_put(b2, &c, 1);
		assert(buffer_pending(b1) == 1);
		assert(buffer_pending(b2) == 1);
		if (c++ == 'z')
			c = 'a';
		buffer_reset(b1);
		buffer_reset(b2);
		assert(buffer_pending(b1) == 0);
		assert(buffer_pending(b2) == 0);
	}
	buffer_free(b1);
	buffer_free(b2);
	return 0;
}
