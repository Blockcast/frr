// SPDX-License-Identifier: GPL-2.0-or-later
/* Wrap-aware netlink sequence-number ordering
 * Copyright (C) 2026 Blockcast
 */

#ifndef _ZEBRA_NETLINK_SEQ_H
#define _ZEBRA_NETLINK_SEQ_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Netlink sequence numbers come from a free-running 32-bit counter, so
 * ordering between them is serial-number arithmetic (the RFC 1982 shape),
 * never a plain relational compare: a plain compare inverts at the
 * UINT32_MAX -> 0 wrap, where a delayed pre-wrap response (0xffffffff)
 * reads as newer than a post-wrap head and would drain every live
 * context off the batch, orphaning their real acks.
 *
 * a is older than b iff the modular distance from a forward to b is in
 * the lower half of the space. The comparison is ambiguous only at a
 * distance of exactly 2^31, unreachable for a batch whose depth is
 * bounded far below that.
 */
static inline bool nl_seq_lt(uint32_t a, uint32_t b)
{
	return (int32_t)(a - b) < 0;
}

/* The successor of a sequence number, modulo the 32-bit space. Update
 * contexts consume two consecutive numbers, including across the wrap,
 * so their partner response is nl_seq_next(seq), not seq + 1 computed
 * in a signed type (undefined at INT_MAX). */
static inline uint32_t nl_seq_next(uint32_t seq)
{
	return seq + 1;
}

#ifdef __cplusplus
}
#endif

#endif /* _ZEBRA_NETLINK_SEQ_H */
