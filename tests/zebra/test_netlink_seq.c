// SPDX-License-Identifier: GPL-2.0-or-later
/* Wrap-aware netlink sequence ordering tests.
 * Copyright (C) 2026 Blockcast
 *
 * Regression for the nl_batch_read_resp stale-response guard: sequence
 * ordering must survive the UINT32_MAX -> 0 counter wrap, including an
 * update context that consumes two consecutive sequence numbers across
 * the wrap. A plain relational compare reads a delayed pre-wrap
 * response as newer than a post-wrap head and drains the batch.
 */

#include <zebra.h>

#include "zebra/netlink_seq.h"

static void check_lt(uint32_t a, uint32_t b, bool want)
{
	bool got = nl_seq_lt(a, b);

	printf("nl_seq_lt(0x%08x, 0x%08x) = %s: %s\n", a, b,
	       got ? "true" : "false", got == want ? "OK" : "FAIL");
}

static void check_next(uint32_t seq, uint32_t want)
{
	uint32_t got = nl_seq_next(seq);

	printf("nl_seq_next(0x%08x) = 0x%08x: %s\n", seq, got,
	       got == want ? "OK" : "FAIL");
}

int main(int argc, char **argv)
{
	/* Mid-space ordering: behaves exactly like a plain compare. */
	check_lt(4, 5, true);
	check_lt(5, 5, false);
	check_lt(6, 5, false);

	/*
	 * The wrap regression: the head context sits at a post-wrap
	 * sequence and a delayed pre-wrap response arrives. It must
	 * order as OLDER (stale, dropped); a plain compare orders it
	 * newer and dequeues live contexts until the batch is empty.
	 */
	check_lt(UINT32_MAX, 0, true);
	check_lt(0, UINT32_MAX, false);
	check_lt(0xfffffff0, 3, true);
	check_lt(3, 0xfffffff0, false);

	/*
	 * Update contexts consume two consecutive sequence numbers.
	 * The partner response of an update head at UINT32_MAX is 0:
	 * successor arithmetic is modulo the 32-bit space, and the
	 * partner must NOT order as stale relative to its own head.
	 */
	check_next(5, 6);
	check_next(UINT32_MAX, 0);
	check_lt(nl_seq_next(UINT32_MAX), UINT32_MAX, false);

	/*
	 * The producer path (netlink_batch_add_msg) tags an update's
	 * second message with the modular successor of a uint32_t
	 * sequence. INT_MAX is the boundary where the previous signed
	 * increment was undefined behavior; ordering must also hold
	 * across the sign boundary, where a signed compare inverts.
	 */
	check_next(0x7fffffff, 0x80000000);
	check_lt(0x7fffffff, 0x80000000, true);
	check_lt(0x80000000, 0x7fffffff, false);

	return 0;
}
