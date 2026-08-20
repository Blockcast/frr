// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Event-grade Type-7 (C-multicast Source Tree Join) install/withdraw/
 * origin-change emission for settlement-plane consumers.
 *
 * Copyright (C) 2026 Blockcast, Inc.
 *
 * See bgp_mvpn_events.h and doc/mvpn-events-schema.md for the contract this
 * file implements. Summary: one JSON object per line on an AF_UNIX
 * SOCK_STREAM listener, one line per Type-7 lifecycle transition
 * (install/withdraw/origin_change) for a locally-originated (pimd-driven)
 * join, broadcast to every connected reader.
 *
 * Durable cursor: every event carries (boot_epoch, seq). Both are scoped to
 * one *listener instance*: `seq` is an in-memory counter starting at 1 that
 * resets whenever the listener is (re)created -- it is NOT fsynced per
 * event, because the only thing that must survive a restart is the ability
 * to tell "the producer restarted" apart from "events were lost between two
 * events of the same epoch". `boot_epoch` is a small counter persisted under
 * frr_libstatedir and incremented on every listener start -- a bgpd restart
 * is the common cause, but reconfiguring `bgp mvpn event-socket` (no + re-add,
 * or a path change) within one process bumps it too. Either way a consumer
 * that tracks (last_epoch, last_seq) detects a gap whenever the next event's
 * (epoch, seq) does not equal (last_epoch, last_seq + 1) exactly -- whether
 * the discontinuity came from a producer (re)start, a dropped/reconnected
 * client socket (see BGP_MVPN_EVENT_SINK_MAX_BACKLOG below), or genuine
 * event loss. Per BLO-17645: "gap -> quarantine, not silent loss".
 *
 * route_version is scoped per (src, grp) join identity, not global: it is
 * the opaque string "<boot_epoch>.<generation>", where generation increments
 * on every install, withdraw, and origin_change for that join (never reused
 * across a leave/rejoin cycle within one boot), matching the MVPN Delivery
 * Settlement Contract v1 rule that route_version changes on any install,
 * withdraw, or LC-UMH origin change.
 */
#include <zebra.h>

#include <sys/un.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>

#include "memory.h"
#include "log.h"
#include "lib_errors.h"
#include "network.h"
#include "buffer.h"
#include "frrevent.h"
#include "command.h"
#include "vty.h"
#include "vrf.h"
#include "libfrr.h"
#include "json.h"
/* enum zapi_mvpn_sg_forwarding / zapi_mvpn_sg_fwd_reason: the readiness state
 * and cause that the forwarding_* events report. */
#include "zclient.h"

#include "bgpd/bgpd.h"
#include "bgpd/bgp_table.h"
#include "bgpd/bgp_route.h"
#include "bgpd/bgp_mvpn.h"
#include "bgpd/bgp_mvpn_events.h"

DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_SINK, "MVPN event sink");
DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_CLIENT, "MVPN event sink client");
DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_JOIN, "MVPN event join state");
DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_LEAF, "MVPN event leaf state");
DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_PATH, "MVPN event socket path");
DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_LINE, "MVPN event wire line");

/* A slow/wedged reader is disconnected rather than buffered without bound --
 * an unbounded queue would turn a stalled consumer into unbounded bgpd
 * memory growth on a settlement-critical path. Disconnection is the gap
 * signal (see file header): the client's next connection restarts its read
 * at whatever seq is current, and the seq discontinuity is exactly what
 * tells it bytes were lost in between. */
struct bgp_mvpn_event_client {
	struct bgp_mvpn_event_client *next;
	int fd;
	struct buffer *wb;
	struct event *t_read;
	struct event *t_write;
	struct bgp_mvpn_event_sink *sink; /* back-pointer for the write callback */
	char read_buf[256];
	size_t read_len;
	bool subscribed;
	bool snapshot_offered;
	bool snapshot_ready;
	bool has_cursor;
	uint64_t cursor_boot_epoch;
	uint64_t cursor_seq;
	uint64_t snapshot_seq;
};

struct bgp_mvpn_event_join {
	struct bgp_mvpn_event_join *next;
	struct ipaddr src;
	struct ipaddr grp;
	uint32_t generation;
	bool installed;
	uint32_t last_source_as;
	struct in_addr last_umh;
	/*
	 * Whether a "forwarding_ready" has been emitted for the CURRENT
	 * route-state interval, i.e. the open readiness interval.
	 *
	 * This is the exactly-once latch for both edges: it gates
	 * "forwarding_lost" (D3 "Failed": never emit one for a path that never
	 * reported ready) and it suppresses duplicate "forwarding_ready" when
	 * pimd re-ADDs a still-READY (S,G).
	 *
	 * Cleared on withdraw and on origin_change, so a readiness interval
	 * never straddles a route_version change (D3 "Origin change").  NOT
	 * carried in the snapshot: a restarted bgpd has no readiness state and
	 * emits nothing until pimd re-reports (D4 restart matrix).
	 */
	bool forwarding_ready;
};

struct bgp_mvpn_event_sink {
	struct bgp *bgp;
	char *path;
	int listen_fd;
	struct event *t_accept;
	struct bgp_mvpn_event_client *clients;
	uint64_t boot_epoch;
	uint64_t seq;
	struct bgp_mvpn_event_join *joins;
	struct bgp_mvpn_event_leaf *leaves;
	bool snapshot_pending;
	bool snapshot_replay_active;
	bool snapshot_delivery_failed;
	uint64_t snapshot_index;
	struct bgp_mvpn_event_client *snapshot_client;
	struct event *t_snapshot_offer;
	struct event *t_leaf_reconcile;
};

/*
 * Per-leaf settlement state, keyed (C-S, C-G, leaf).
 *
 * A join is per (C-S, C-G) because it describes THIS PE's own upstream
 * interest. A leaf is one level deeper: under ingress replication the root
 * replicates one (C-S, C-G) stream to many leaves, and settlement bills each
 * of them separately. The leaf identity is the Type-4 (Leaf A-D) route's
 * leaf_originator -- the leaf PE's router-id, already carried in the MVPN RIB
 * key by bgp_mvpn_build_prefix_type4().
 *
 * `seen` is reconcile scratch, not state: cleared at the start of a walk, set
 * for every leaf still present in the RIB, and anything left clear afterwards
 * is withdrawn. That makes the walk idempotent and self-correcting -- a
 * trigger this file fails to hook costs latency on the next walk, never a
 * wrong bill, which is the failure direction a settlement path wants.
 */
struct bgp_mvpn_event_leaf {
	struct bgp_mvpn_event_leaf *next;
	struct ipaddr src;
	struct ipaddr grp;
	struct ipaddr leaf;
	uint32_t generation;
	bool installed;
	bool seen;
};

static bool bgp_mvpn_event_deliver(struct bgp_mvpn_event_sink *sink,
				   struct bgp_mvpn_event_client *target,
				   struct json_object *jo);
static void bgp_mvpn_event_snapshot_offer_next(struct bgp_mvpn_event_sink *sink);

static void bgp_mvpn_event_snapshot_offer_event(struct event *event)
{
	struct bgp_mvpn_event_sink *sink = EVENT_ARG(event);

	bgp_mvpn_event_snapshot_offer_next(sink);
}

static void bgp_mvpn_event_snapshot_schedule(struct bgp_mvpn_event_sink *sink)
{
	event_add_event(bm->master, bgp_mvpn_event_snapshot_offer_event, sink, 0,
			&sink->t_snapshot_offer);
}

static const char *bgp_mvpn_event_cursor_status(const struct bgp_mvpn_event_sink *sink,
						 const struct bgp_mvpn_event_client *client)
{
	if (!client->has_cursor)
		return "bootstrap";
	if (client->cursor_boot_epoch < sink->boot_epoch)
		return "boot_boundary";
	if (client->cursor_boot_epoch > sink->boot_epoch ||
	    client->cursor_seq > client->snapshot_seq)
		return "rollback";
	if (client->cursor_seq < client->snapshot_seq)
		return "gap";
	return "contiguous";
}

static void bgp_mvpn_event_client_close(struct bgp_mvpn_event_sink *sink,
					struct bgp_mvpn_event_client *client)
{
	struct bgp_mvpn_event_client **pp;
	bool snapshot_owner = sink->snapshot_client == client;

	for (pp = &sink->clients; *pp; pp = &(*pp)->next)
		if (*pp == client) {
			*pp = client->next;
			break;
		}
	if (snapshot_owner)
		sink->snapshot_client = NULL;

	event_cancel(&client->t_read);
	event_cancel(&client->t_write);
	buffer_free(client->wb);
	close(client->fd);
	XFREE(MTYPE_MVPN_EVENT_CLIENT, client);

	if (snapshot_owner && sink->snapshot_pending &&
	    !sink->snapshot_replay_active)
		bgp_mvpn_event_snapshot_schedule(sink);
}

static bool bgp_mvpn_event_snapshot_offer(struct bgp_mvpn_event_sink *sink,
					  struct bgp_mvpn_event_client *client)
{
	struct json_object *end;

	if (!sink->snapshot_pending || sink->snapshot_client ||
	    !client->subscribed || client->snapshot_offered)
		return true;

	sink->snapshot_client = client;
	client->snapshot_offered = true;
	client->snapshot_seq = sink->seq;
	sink->snapshot_replay_active = true;
	sink->snapshot_delivery_failed = false;
	sink->snapshot_index = 0;
	bgp_mvpn_reemit_local_joins(sink->bgp);
	/* A subscriber that only saw joins would have no leaf set at all until
	 * the next RIB change, and would bill nothing per-leaf in the meantime. */
	bgp_mvpn_events_reconcile_leaves(sink->bgp);
	sink->snapshot_replay_active = false;

	/* Private delivery may synchronously close the owner. Defer promotion so
	 * an outer client-list traversal can unwind before another replay closes
	 * or unlinks clients. */
	if (sink->snapshot_client != client) {
		bgp_mvpn_event_snapshot_schedule(sink);
		return false;
	}
	if (sink->snapshot_delivery_failed) {
		bgp_mvpn_event_client_close(sink, client);
		return false;
	}
	end = json_object_new_object();
	if (!end) {
		sink->snapshot_delivery_failed = true;
		bgp_mvpn_event_client_close(sink, client);
		return false;
	}
	json_object_int_add(end, "schema_version", 1);
	json_object_string_add(end, "type", "snapshot_end");
	json_object_int_add(end, "boot_epoch", (int64_t)sink->boot_epoch);
	json_object_int_add(end, "seq", (int64_t)client->snapshot_seq);
	json_object_int_add(end, "snapshot_count", (int64_t)sink->snapshot_index);
	json_object_string_add(end, "cursor_status",
			       bgp_mvpn_event_cursor_status(sink, client));
	if (!bgp_mvpn_event_deliver(sink, client, end))
		return false;

	/* Waiting for one client's durable ACK must not stall snapshot handoff to
	 * every later subscriber. The client's socket remains ordered: live events
	 * follow snapshot_end while the next private replay is offered separately. */
	if (sink->snapshot_client == client) {
		sink->snapshot_client = NULL;
		bgp_mvpn_event_snapshot_schedule(sink);
	}
	return true;
}

static void bgp_mvpn_event_snapshot_offer_next(struct bgp_mvpn_event_sink *sink)
{
	struct bgp_mvpn_event_client *client;

	if (!sink->snapshot_pending || sink->snapshot_client ||
	    sink->snapshot_replay_active)
		return;
	for (client = sink->clients; client; client = client->next)
		if (client->subscribed && !client->snapshot_offered) {
			(void)bgp_mvpn_event_snapshot_offer(sink, client);
			return;
		}
}

static void bgp_mvpn_event_client_write(struct event *event)
{
	struct bgp_mvpn_event_client *client = EVENT_ARG(event);
	struct bgp_mvpn_event_sink *sink = client->sink;
	buffer_status_t status;

	status = buffer_flush_available(client->wb, client->fd);
	if (status == BUFFER_ERROR) {
		bgp_mvpn_event_client_close(sink, client);
		return;
	}
	if (status == BUFFER_EMPTY)
		return;
	event_add_write(bm->master, bgp_mvpn_event_client_write, client, client->fd,
			&client->t_write);
}

/* The read side handles the small subscribe/snapshot-ack control protocol and
 * notices peer shutdown. Lifecycle events remain producer -> consumer only. */
static void bgp_mvpn_event_client_read(struct event *event)
{
	struct bgp_mvpn_event_client *client = EVENT_ARG(event);
	struct bgp_mvpn_event_sink *sink = client->sink;
	ssize_t n;
	char *newline;

	n = read(client->fd, client->read_buf + client->read_len,
		 sizeof(client->read_buf) - client->read_len - 1);
	/* n == 0 is EOF, unconditionally: read() does not touch errno on a
	 * clean peer close, so gating it on a (stale) errno value would leave
	 * a dead client unreaped with its socket perpetually POLLIN-ready --
	 * a 100% CPU rearm loop. errno is only meaningful for n < 0. */
	if (n == 0 ||
	    (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
		bgp_mvpn_event_client_close(sink, client);
		return;
	}
	if (n > 0) {
		client->read_len += n;
		client->read_buf[client->read_len] = '\0';
	}

	while ((newline = memchr(client->read_buf, '\n', client->read_len))) {
		struct json_object *jo;
		struct json_object *type;
		struct json_object *epoch;
		struct json_object *seq;
		struct json_object *cursor_epoch;
		struct json_object *cursor_seq;
		size_t line_len = newline - client->read_buf;
		bool client_closed = false;

		*newline = '\0';
		jo = json_tokener_parse(client->read_buf);
		if (jo && json_object_object_get_ex(jo, "type", &type) &&
		    json_object_is_type(type, json_type_string) &&
		    strcmp(json_object_get_string(type), "subscribe") == 0) {
			bool have_epoch = json_object_object_get_ex(
				jo, "last_boot_epoch", &cursor_epoch);
			bool have_seq = json_object_object_get_ex(jo, "last_seq", &cursor_seq);

			if (have_epoch != have_seq ||
			    (have_epoch &&
			     (!json_object_is_type(cursor_epoch, json_type_int) ||
			      !json_object_is_type(cursor_seq, json_type_int) ||
			      json_object_get_int64(cursor_epoch) < 0 ||
			      json_object_get_int64(cursor_seq) < 0))) {
				zlog_warn("MVPN events: client fd %d sent an invalid durable cursor",
					  client->fd);
				bgp_mvpn_event_client_close(sink, client);
				client_closed = true;
			} else {
				client->has_cursor = have_epoch;
				if (have_epoch) {
					client->cursor_boot_epoch =
						(uint64_t)json_object_get_int64(cursor_epoch);
					client->cursor_seq =
						(uint64_t)json_object_get_int64(cursor_seq);
				}
				client->subscribed = true;
				client_closed =
					!bgp_mvpn_event_snapshot_offer(sink, client);
			}
		} else if (jo && json_object_object_get_ex(jo, "type", &type) &&
			   json_object_is_type(type, json_type_string) &&
			   strcmp(json_object_get_string(type), "snapshot_ack") == 0 &&
			   json_object_object_get_ex(jo, "boot_epoch", &epoch) &&
			   json_object_object_get_ex(jo, "seq", &seq) &&
			   client->snapshot_offered &&
			   (uint64_t)json_object_get_int64(epoch) == sink->boot_epoch &&
			   (uint64_t)json_object_get_int64(seq) == client->snapshot_seq) {
			client->snapshot_ready = true;
		}
		/* Private delivery can synchronously close and free its owner. Do not
		 * touch the read buffer or rearm an event against that stale pointer. */
		if (client_closed) {
			if (jo)
				json_object_put(jo);
			return;
		}
		if (jo)
			json_object_put(jo);

		line_len++;
		client->read_len -= line_len;
		memmove(client->read_buf, client->read_buf + line_len, client->read_len);
		client->read_buf[client->read_len] = '\0';
	}
	if (client->read_len == sizeof(client->read_buf) - 1) {
		zlog_warn("MVPN events: client fd %d sent an oversized control record",
			  client->fd);
		bgp_mvpn_event_client_close(sink, client);
		return;
	}

	event_add_read(bm->master, bgp_mvpn_event_client_read, client, client->fd,
		       &client->t_read);
}

static void bgp_mvpn_event_accept(struct event *event)
{
	struct bgp_mvpn_event_sink *sink = EVENT_ARG(event);
	struct bgp_mvpn_event_client *client;
	int fd;

	event_add_read(bm->master, bgp_mvpn_event_accept, sink, sink->listen_fd,
		       &sink->t_accept);

	fd = accept(sink->listen_fd, NULL, NULL);
	if (fd < 0) {
		if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
			flog_err(EC_LIB_SOCKET, "MVPN event socket accept failed: %s",
				 safe_strerror(errno));
		return;
	}

	/* A blocking fd would let a slow consumer stall the whole master
	 * thread inside buffer_write()'s write(): refuse the client rather
	 * than let a billing reader wedge routing. */
	if (set_nonblocking(fd) < 0) {
		flog_err(EC_LIB_SOCKET,
			 "MVPN event socket: set_nonblocking(client fd %d) failed: %s -- refusing client",
			 fd, safe_strerror(errno));
		close(fd);
		return;
	}

	client = XCALLOC(MTYPE_MVPN_EVENT_CLIENT, sizeof(*client));
	client->fd = fd;
	client->wb = buffer_new(0);
	client->sink = sink;
	client->next = sink->clients;
	sink->clients = client;

	event_add_read(bm->master, bgp_mvpn_event_client_read, client, fd, &client->t_read);

}

/*
 * The durable half of the cursor: a small text file under frr_libstatedir
 * holding the next boot_epoch to hand out, read-incremented-written under an
 * exclusive lock so two bgpd processes (or bgpd + a stray leftover) can never
 * be handed the same epoch. libstatedir is persistent across host reboot, so a
 * producer cannot reuse an epoch while a durable downstream cursor still
 * references it. Persistence failure is fail-closed: no listener is started.
 */
static bool bgp_mvpn_event_next_boot_epoch(const char *instance_name, uint64_t *result)
{
	char path[512], lock_path[512], tmp_path[544];
	int fd = -1, lock_fd = -1, dir_fd = -1;
	uint64_t epoch = 1;
	char buf[32];
	ssize_t n;
	char *end;
	bool ok = false;

	if (snprintf(path, sizeof(path), "%s/bgpd-mvpn-events-%s.epoch", frr_libstatedir,
		     (instance_name && instance_name[0]) ? instance_name : "default") >=
	    (int)sizeof(path) ||
	    snprintf(lock_path, sizeof(lock_path), "%s.lock", path) >=
		    (int)sizeof(lock_path)) {
		flog_err(EC_LIB_SYSTEM_CALL, "MVPN event boot_epoch path is too long");
		return false;
	}

	lock_fd = open(lock_path, O_RDWR | O_CREAT, 0600);
	if (lock_fd < 0 || lockf(lock_fd, F_TLOCK, 0) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL,
			 "MVPN event boot_epoch lock %s failed: %s", lock_path,
			 safe_strerror(errno));
		goto out;
	}

	fd = open(path, O_RDONLY);
	if (fd >= 0) {
		n = read(fd, buf, sizeof(buf) - 1);
		if (n <= 0 || n == (ssize_t)sizeof(buf) - 1) {
			flog_err(EC_LIB_SYSTEM_CALL,
				 "MVPN event boot_epoch file %s is empty or oversized", path);
			goto out;
		}
		buf[n] = '\0';
		errno = 0;
		epoch = strtoull(buf, &end, 10);
		if (errno || end == buf || *end != '\0' || epoch == UINT64_MAX) {
			flog_err(EC_LIB_SYSTEM_CALL,
				 "MVPN event boot_epoch file %s is invalid", path);
			goto out;
		}
		epoch++;
		close(fd);
		fd = -1;
	} else if (errno != ENOENT) {
		flog_err(EC_LIB_SYSTEM_CALL, "MVPN event boot_epoch file %s open failed: %s",
			 path, safe_strerror(errno));
		goto out;
	}

	n = snprintf(buf, sizeof(buf), "%" PRIu64, epoch);
	snprintf(tmp_path, sizeof(tmp_path), "%s.XXXXXX", path);
	fd = mkstemp(tmp_path);
	if (fd < 0 || fchmod(fd, 0600) < 0 || write(fd, buf, n) != n || fsync(fd) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL,
			 "MVPN event boot_epoch file %s update failed: %s",
			 path, safe_strerror(errno));
		if (fd >= 0) {
			close(fd);
			fd = -1;
		}
		unlink(tmp_path);
		goto out;
	}
	if (close(fd) < 0) {
		fd = -1;
		flog_err(EC_LIB_SYSTEM_CALL, "MVPN event boot_epoch file %s close failed: %s",
			 path, safe_strerror(errno));
		unlink(tmp_path);
		goto out;
	}
	fd = -1;
	if (rename(tmp_path, path) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL, "MVPN event boot_epoch rename to %s failed: %s",
			 path, safe_strerror(errno));
		unlink(tmp_path);
		goto out;
	}
	dir_fd = open(frr_libstatedir, O_RDONLY | O_DIRECTORY);
	if (dir_fd < 0 || fsync(dir_fd) < 0) {
		flog_err(EC_LIB_SYSTEM_CALL, "MVPN event boot_epoch directory sync failed: %s",
			 safe_strerror(errno));
		goto out;
	}

	*result = epoch;
	ok = true;
out:
	if (fd >= 0)
		close(fd);
	if (dir_fd >= 0)
		close(dir_fd);
	if (lock_fd >= 0)
		close(lock_fd);
	return ok;
}

static struct bgp_mvpn_event_sink *bgp_mvpn_events_start(struct bgp *bgp,
							 const char *path)
{
	struct bgp_mvpn_event_sink *sink;
	struct sockaddr_un sun;
	struct stat st;
	mode_t old_mask;
	int fd, probe_fd;
	uint64_t boot_epoch;

	if (strlen(path) >= sizeof(sun.sun_path)) {
		flog_err(EC_LIB_SYSTEM_CALL, "MVPN event socket path %s too long",
			 path);
		return NULL;
	}
	if (!bgp_mvpn_event_next_boot_epoch(bgp->name ? bgp->name : VRF_DEFAULT_NAME,
					    &boot_epoch))
		return NULL;

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, path, sizeof(sun.sun_path));
	if (lstat(path, &st) == 0) {
		if (!S_ISSOCK(st.st_mode)) {
			flog_err(EC_LIB_SOCKET, "MVPN event socket path %s is not a socket", path);
			return NULL;
		}
		probe_fd = socket(AF_UNIX, SOCK_STREAM, 0);
		if (probe_fd < 0 || set_nonblocking(probe_fd) < 0) {
			if (probe_fd >= 0)
				close(probe_fd);
			return NULL;
		}
		if (connect(probe_fd, (struct sockaddr *)&sun, sizeof(sun)) == 0) {
			close(probe_fd);
			flog_err(EC_LIB_SOCKET, "MVPN event socket path %s is already active", path);
			return NULL;
		}
		if (errno == EINPROGRESS || errno == EAGAIN) {
			close(probe_fd);
			flog_err(EC_LIB_SOCKET, "MVPN event socket path %s is already active", path);
			return NULL;
		}
		if (errno != ECONNREFUSED) {
			flog_err(EC_LIB_SOCKET, "MVPN event socket path %s cannot be probed: %s",
				 path, safe_strerror(errno));
			close(probe_fd);
			return NULL;
		}
		close(probe_fd);
		if (unlink(path) < 0) {
			flog_err(EC_LIB_SOCKET, "MVPN stale event socket %s cannot be removed: %s",
				 path, safe_strerror(errno));
			return NULL;
		}
	} else if (errno != ENOENT) {
		flog_err(EC_LIB_SOCKET, "MVPN event socket path %s cannot be inspected: %s",
			 path, safe_strerror(errno));
		return NULL;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		flog_err(EC_LIB_SOCKET, "MVPN event socket() failed: %s", safe_strerror(errno));
		return NULL;
	}

	old_mask = umask(0077);
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		flog_err(EC_LIB_SOCKET, "MVPN event socket bind(%s) failed: %s", sun.sun_path,
			 safe_strerror(errno));
		umask(old_mask);
		close(fd);
		return NULL;
	}
	umask(old_mask);

	if (listen(fd, 8) < 0) {
		flog_err(EC_LIB_SOCKET, "MVPN event socket listen(%s) failed: %s", sun.sun_path,
			 safe_strerror(errno));
		close(fd);
		unlink(sun.sun_path);
		return NULL;
	}

	if (set_nonblocking(fd) < 0) {
		flog_err(EC_LIB_SOCKET,
			 "MVPN event socket: set_nonblocking(%s) failed: %s",
			 sun.sun_path, safe_strerror(errno));
		unlink(sun.sun_path);
		close(fd);
		return NULL;
	}

	sink = XCALLOC(MTYPE_MVPN_EVENT_SINK, sizeof(*sink));
	sink->bgp = bgp;
	sink->path = XSTRDUP(MTYPE_MVPN_EVENT_PATH, path);
	sink->listen_fd = fd;
	sink->boot_epoch = boot_epoch;
	sink->seq = 0;
	sink->snapshot_pending = true;
	event_add_read(bm->master, bgp_mvpn_event_accept, sink, fd, &sink->t_accept);

	zlog_info("MVPN events: listening on %s (boot_epoch %" PRIu64 ")", sun.sun_path,
		  sink->boot_epoch);
	return sink;
}

void bgp_mvpn_events_stop(struct bgp *bgp)
{
	struct bgp_mvpn_event_sink *sink = bgp->mvpn_event_sink;
	struct bgp_mvpn_event_join *join;
	struct bgp_mvpn_event_leaf *leaf;

	if (!sink)
		return;

	sink->snapshot_pending = false;
	event_cancel(&sink->t_snapshot_offer);
	event_cancel(&sink->t_leaf_reconcile);
	while (sink->clients)
		bgp_mvpn_event_client_close(sink, sink->clients);

	event_cancel(&sink->t_accept);
	if (sink->listen_fd >= 0) {
		unlink(sink->path);
		close(sink->listen_fd);
	}

	while (sink->joins) {
		join = sink->joins;
		sink->joins = join->next;
		XFREE(MTYPE_MVPN_EVENT_JOIN, join);
	}

	while (sink->leaves) {
		leaf = sink->leaves;
		sink->leaves = leaf->next;
		XFREE(MTYPE_MVPN_EVENT_LEAF, leaf);
	}

	XFREE(MTYPE_MVPN_EVENT_PATH, sink->path);
	XFREE(MTYPE_MVPN_EVENT_SINK, sink);
	bgp->mvpn_event_sink = NULL;
}

int bgp_mvpn_events_set_socket(struct bgp *bgp, const char *path)
{
	struct bgp_mvpn_event_sink *replacement;
	char *configured_path;

	if (!path) {
		bgp_mvpn_events_stop(bgp);
		XFREE(MTYPE_MVPN_EVENT_PATH, bgp->mvpn_event_socket_path);
		return CMD_SUCCESS;
	}
	if (bgp->mvpn_event_sink && strcmp(bgp->mvpn_event_sink->path, path) == 0)
		return CMD_SUCCESS;

	replacement = bgp_mvpn_events_start(bgp, path);
	if (!replacement) {
		/* Preserve operator intent after failed initial/config-replay startup so
		 * running-config and `show` expose configured-but-not-listening. A failed
		 * replacement must retain the healthy listener and its old path. */
		if (!bgp->mvpn_event_sink) {
			configured_path = XSTRDUP(MTYPE_MVPN_EVENT_PATH, path);
			XFREE(MTYPE_MVPN_EVENT_PATH, bgp->mvpn_event_socket_path);
			bgp->mvpn_event_socket_path = configured_path;
		}
		return CMD_WARNING_CONFIG_FAILED;
	}
	configured_path = XSTRDUP(MTYPE_MVPN_EVENT_PATH, path);
	bgp_mvpn_events_stop(bgp);
	XFREE(MTYPE_MVPN_EVENT_PATH, bgp->mvpn_event_socket_path);
	bgp->mvpn_event_socket_path = configured_path;
	bgp->mvpn_event_sink = replacement;
	return CMD_SUCCESS;
}

void bgp_mvpn_events_config_write(struct vty *vty, struct bgp *bgp)
{
	if (bgp->mvpn_event_socket_path)
		vty_out(vty, "  bgp mvpn event-socket %s\n", bgp->mvpn_event_socket_path);
}

/*
 * Listener liveness for operators: `bgp mvpn event-socket` in running-config
 * only proves the path is *configured* -- a bind/listen failure at startup
 * (stale socket file, parent dir not mounted yet at config replay) leaves the
 * feature dead while the config still advertises it. "configured but not
 * listening" here is the alarm the settlement pipeline must page on.
 */
void bgp_mvpn_events_show(struct vty *vty, struct bgp *bgp, bool use_json)
{
	struct bgp_mvpn_event_sink *sink = bgp->mvpn_event_sink;
	struct bgp_mvpn_event_client *client;
	int clients = 0, subscribed_clients = 0;

	if (sink)
		for (client = sink->clients; client; client = client->next) {
			clients++;
			if (client->subscribed)
				subscribed_clients++;
		}

	if (use_json) {
		struct json_object *jo = json_object_new_object();

		if (!jo)
			return;
		if (bgp->mvpn_event_socket_path)
			json_object_string_add(jo, "path", bgp->mvpn_event_socket_path);
		json_object_boolean_add(jo, "listening", sink != NULL);
		if (sink) {
			json_object_int_add(jo, "bootEpoch", (int64_t)sink->boot_epoch);
			json_object_int_add(jo, "seq", (int64_t)sink->seq);
			json_object_int_add(jo, "clients", clients);
			json_object_int_add(jo, "subscribedClients", subscribed_clients);
		}
		vty_json(vty, jo);
		return;
	}

	if (!bgp->mvpn_event_socket_path) {
		vty_out(vty, "MVPN event socket not configured\n");
		return;
	}
	vty_out(vty, "MVPN event socket %s: %s\n", bgp->mvpn_event_socket_path,
		sink ? "listening" : "NOT LISTENING (startup failed; see log)");
	if (sink)
		vty_out(vty, "  boot_epoch %" PRIu64 ", seq %" PRIu64 ", %d client(s)\n",
			sink->boot_epoch, sink->seq, clients);
}

static struct bgp_mvpn_event_join *bgp_mvpn_event_join_find(struct bgp_mvpn_event_sink *sink,
							     const struct ipaddr *src,
							     const struct ipaddr *grp)
{
	struct bgp_mvpn_event_join *join;

	for (join = sink->joins; join; join = join->next)
		if (ipaddr_cmp(&join->src, src) == 0 && ipaddr_cmp(&join->grp, grp) == 0)
			return join;
	return NULL;
}

static struct bgp_mvpn_event_join *bgp_mvpn_event_join_get(struct bgp_mvpn_event_sink *sink,
							    const struct ipaddr *src,
							    const struct ipaddr *grp)
{
	struct bgp_mvpn_event_join *join = bgp_mvpn_event_join_find(sink, src, grp);

	if (join)
		return join;

	join = XCALLOC(MTYPE_MVPN_EVENT_JOIN, sizeof(*join));
	join->src = *src;
	join->grp = *grp;
	join->next = sink->joins;
	sink->joins = join;
	return join;
}

/* RFC 6514 Section 5 / draft-ietf-mboned-dimt encoding, matching the
 * settlement contract's SessionLease.lc_umh_origin field byte-for-byte
 * (BLO-17643, Section 4): "<sourceAS>:1:<UMH-u32>". The literal "1" is the
 * function code point this contract fixes for the resolved-origin
 * attestation -- distinct from the operator-configured
 * `bgp mvpn umh-large-community <function>` decode knob, which selects which
 * function code point bgpd itself trusts on the wire.
 */
static void bgp_mvpn_event_lc_umh_origin(char *buf, size_t buflen, uint32_t source_as,
					 struct in_addr umh)
{
	if (umh.s_addr == INADDR_ANY) {
		buf[0] = '\0';
		return;
	}
	snprintf(buf, buflen, "%u:1:%u", source_as, ntohl(umh.s_addr));
}

static void bgp_mvpn_event_route_version(char *buf, size_t buflen, uint64_t boot_epoch,
					 uint32_t generation)
{
	snprintf(buf, buflen, "%" PRIu64 ".%u", boot_epoch, generation);
}

static bool bgp_mvpn_event_deliver(struct bgp_mvpn_event_sink *sink,
				   struct bgp_mvpn_event_client *target,
				   struct json_object *jo)
{
	const char *text;
	char *line;
	size_t textlen, linelen;
	struct bgp_mvpn_event_client *client, *next;
	bool delivered = target == NULL;

	text = json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PLAIN);
	textlen = strlen(text);
	linelen = textlen + 1;
	line = XMALLOC(MTYPE_MVPN_EVENT_LINE, linelen);
	memcpy(line, text, textlen);
	line[textlen] = '\n';

	for (client = sink->clients; client; client = next) {
		buffer_status_t status;

		next = client->next;
		if (!client->subscribed || (target && client != target))
			continue;
		/* Once snapshot_end is queued, socket ordering keeps subsequent live
		 * records behind that baseline even while its durable ACK is pending. */
		if (!target && !client->snapshot_ready && !client->snapshot_offered)
			continue;

		if (bgp_mvpn_event_backlog_exceeded(client->wb, linelen)) {
			zlog_warn("MVPN events: client fd %d exceeded %u byte backlog, disconnecting (gap signal for reconnect)",
				  client->fd, BGP_MVPN_EVENT_SINK_MAX_BACKLOG);
			if (client == target)
				sink->snapshot_delivery_failed = true;
			bgp_mvpn_event_client_close(sink, client);
			continue;
		}

		status = buffer_write(client->wb, client->fd, line, linelen);
		if (status == BUFFER_ERROR) {
			if (client == target)
				sink->snapshot_delivery_failed = true;
			bgp_mvpn_event_client_close(sink, client);
			continue;
		}
		delivered = true;
		if (status == BUFFER_EMPTY)
			continue;

		if (!client->t_write)
			event_add_write(bm->master, bgp_mvpn_event_client_write, client,
					client->fd, &client->t_write);
	}

	XFREE(MTYPE_MVPN_EVENT_LINE, line);
	json_object_free(jo);
	return delivered;
}

bool bgp_mvpn_event_backlog_exceeded(const struct buffer *wb, size_t append_len)
{
	size_t pending = buffer_pending(wb);

	return pending > BGP_MVPN_EVENT_SINK_MAX_BACKLOG ||
	       append_len > BGP_MVPN_EVENT_SINK_MAX_BACKLOG - pending;
}

static void bgp_mvpn_event_broadcast(struct bgp_mvpn_event_sink *sink,
				     struct json_object *jo)
{
	(void)bgp_mvpn_event_deliver(sink, NULL, jo);
}

static struct json_object *bgp_mvpn_event_new(struct bgp_mvpn_event_sink *sink,
					      const char *event_type, const struct ipaddr *src,
					      const struct ipaddr *grp, uint32_t source_as,
					      const char *route_version)
{
	struct json_object *jo;
	struct timespec ts;
	char srcbuf[INET6_ADDRSTRLEN], grpbuf[INET6_ADDRSTRLEN];

	/* Snapshot replay is private point-in-time framing at the current global
	 * cursor baseline. Only producer lifecycle transitions advance seq. */
	if (!sink->snapshot_replay_active)
		sink->seq++;
	/* Reserve the cursor before json-c's fallible allocation. If allocation
	 * fails, the next successful event exposes the missing sequence instead
	 * of silently losing a settlement transition. */
	jo = json_object_new_object();
	if (!jo) {
		if (sink->snapshot_replay_active)
			sink->snapshot_delivery_failed = true;
		flog_err(EC_LIB_SYSTEM_CALL,
			 "MVPN events: json allocation failed, dropping %s event at seq %" PRIu64
			 " (cursor gap reserved)",
			 event_type, sink->seq);
		return NULL;
	}

	clock_gettime(CLOCK_REALTIME, &ts);

	json_object_int_add(jo, "schema_version", 1);
	json_object_string_add(jo, "event_type", event_type);
	json_object_int_add(jo, "boot_epoch", (int64_t)sink->boot_epoch);
	json_object_int_add(jo, "seq", (int64_t)sink->seq);
	if (sink->snapshot_replay_active) {
		sink->snapshot_index++;
		json_object_boolean_add(jo, "snapshot", true);
		json_object_int_add(jo, "snapshot_index", (int64_t)sink->snapshot_index);
	}
	json_object_int_add(jo, "time_ns", (int64_t)ts.tv_sec * 1000000000LL + ts.tv_nsec);
	json_object_int_add(jo, "route_type", BGP_MVPN_ROUTE_TYPE_SOURCE_TREE_JOIN);
	json_object_string_add(jo, "source", ipaddr2str(src, srcbuf, sizeof(srcbuf)));
	json_object_string_add(jo, "group", ipaddr2str(grp, grpbuf, sizeof(grpbuf)));
	json_object_int_add(jo, "source_as", source_as);
	json_object_string_add(jo, "route_version", route_version);
	/* bgp->name, not name_pretty: the wire contract says "default", and
	 * name_pretty is the human "VRF default" (with a space). */
	json_object_string_add(jo, "vrf",
			       sink->bgp->name ? sink->bgp->name : VRF_DEFAULT_NAME);
	json_object_int_add(jo, "ipmsi_label", sink->bgp->mvpn_ipmsi_label);

	return jo;
}

/* Defined below with the rest of the forwarding-event code; declared here
 * because both lifecycle emitters must close an open readiness interval
 * BEFORE their own record reaches the stream (D3 "Remove" / "Origin
 * change"). */
static void bgp_mvpn_event_forwarding_lost(struct bgp_mvpn_event_sink *sink,
					   struct bgp_mvpn_event_join *join, const char *reason);

void bgp_mvpn_event_join_resolved(struct bgp *bgp, const struct ipaddr *src,
				  const struct ipaddr *grp, uint32_t source_as,
				  struct in_addr umh)
{
	struct bgp_mvpn_event_sink *sink = bgp->mvpn_event_sink;
	struct bgp_mvpn_event_join *join;
	struct json_object *jo;
	char route_version[32], prior_route_version[32], lc_umh_origin[48];
	uint32_t next_generation;
	bool is_new;
	bool changed;

	if (!sink)
		return;
	if (sink->snapshot_replay_active &&
	    (!sink->snapshot_client || sink->snapshot_delivery_failed))
		return;

	join = bgp_mvpn_event_join_get(sink, src, grp);
	is_new = !join->installed;
	changed = !is_new &&
		  (join->last_source_as != source_as || join->last_umh.s_addr != umh.s_addr);

	if (!is_new && !changed && !sink->snapshot_replay_active)
		return; /* redundant re-resolve: same origin as last emitted */

	if (!is_new)
		bgp_mvpn_event_route_version(prior_route_version, sizeof(prior_route_version),
					     sink->boot_epoch, join->generation);

	/* An origin change invalidates the readiness proof: it was established
	 * against the OLD upstream path.  Close the interval before the
	 * origin_change record so a readiness interval never straddles a
	 * route_version change (D3 "Origin change"), and so it closes inside
	 * the entitlement interval that contained it.
	 *
	 * This is ordering only -- it neither gates nor reshapes the
	 * origin_change record that follows.  Emitted before the generation is
	 * bumped below, so the forwarding_lost carries the route_version of the
	 * interval it is closing rather than the new one.
	 *
	 * `changed` is false during snapshot replay for an unchanged join, and
	 * bgp_mvpn_event_forwarding_lost() ignores replay outright, so a
	 * snapshot cannot synthesise this. */
	if (changed)
		bgp_mvpn_event_forwarding_lost(sink, join, "origin_change");

	/* A snapshot describes current state to one subscriber; it is not a
	 * producer lifecycle transition and must not mint a new route_version. */
	next_generation = sink->snapshot_replay_active && !is_new && !changed
				  ? join->generation
				  : join->generation + 1;
	bgp_mvpn_event_route_version(route_version, sizeof(route_version), sink->boot_epoch,
				     next_generation);
	bgp_mvpn_event_lc_umh_origin(lc_umh_origin, sizeof(lc_umh_origin), source_as, umh);

	jo = bgp_mvpn_event_new(sink,
				sink->snapshot_replay_active || is_new ? "install"
								       : "origin_change",
				src, grp, source_as,
				route_version);
	if (jo && lc_umh_origin[0])
		json_object_string_add(jo, "lc_umh_origin", lc_umh_origin);
	if (jo && umh.s_addr != INADDR_ANY) {
		char umhbuf[INET_ADDRSTRLEN];

		json_object_string_add(jo, "upstream_peer",
				       inet_ntop(AF_INET, &umh, umhbuf, sizeof(umhbuf)));
	}
	if (jo && changed)
		json_object_string_add(jo, "prior_route_version", prior_route_version);

	join->generation = next_generation;
	join->installed = true;
	join->last_source_as = source_as;
	join->last_umh = umh;

	if (jo) {
		if (sink->snapshot_replay_active)
			(void)bgp_mvpn_event_deliver(sink, sink->snapshot_client, jo);
		else
			bgp_mvpn_event_broadcast(sink, jo);
	}
}

void bgp_mvpn_event_withdrawn(struct bgp *bgp, const struct ipaddr *src,
			     const struct ipaddr *grp)
{
	struct bgp_mvpn_event_sink *sink = bgp->mvpn_event_sink;
	struct bgp_mvpn_event_join *join;
	struct json_object *jo;
	char route_version[32];
	uint32_t next_generation;

	if (!sink)
		return;

	join = bgp_mvpn_event_join_find(sink, src, grp);
	if (!join || !join->installed)
		return; /* never observed installed by this sink: no window to close */

	/* If forwarding was ready, the readiness interval must close BEFORE the
	 * withdraw, so it always closes inside the entitlement interval that
	 * contained it (D3 "Remove").  Ordering only: the withdraw record's
	 * trigger, timing and shape are untouched, and this is a no-op when no
	 * readiness was ever reported. */
	bgp_mvpn_event_forwarding_lost(sink, join, "withdraw");

	next_generation = join->generation + 1;
	bgp_mvpn_event_route_version(route_version, sizeof(route_version), sink->boot_epoch,
				     next_generation);

	jo = bgp_mvpn_event_new(sink, "withdraw", src, grp, join->last_source_as, route_version);

	join->generation = next_generation;
	join->installed = false;
	join->last_source_as = 0;
	join->last_umh.s_addr = INADDR_ANY;

	if (jo)
		bgp_mvpn_event_broadcast(sink, jo);
}

/*
 * Map pimd's cause byte onto the contract's stable reason enum.
 *
 * The mapping is 1:1 and total.  bgpd never invents a cause: an unspecified
 * byte -- which is what an old pimd, or one that predates the cause field,
 * sends -- renders as "unknown" rather than guessing a specific step.  A
 * wrong-but-plausible reason in a settlement record is worse than an honest
 * "unknown", because a reason string is what a dispute reads.
 */
static const char *bgp_mvpn_event_fwd_reason_str(uint8_t fwd_reason)
{
	switch (fwd_reason) {
	case ZAPI_MVPN_SG_FWD_REASON_TUNNEL_FAIL_INSTALL:
		return "tunnel_fail_install";
	case ZAPI_MVPN_SG_FWD_REASON_TUNNEL_REMOVED:
		return "tunnel_removed";
	case ZAPI_MVPN_SG_FWD_REASON_MFC_EVICTED:
		return "mfc_evicted";
	case ZAPI_MVPN_SG_FWD_REASON_RPF_UNPINNED:
		return "rpf_unpinned";
	case ZAPI_MVPN_SG_FWD_REASON_ANTI_RECURSION_REFUSED:
		return "anti_recursion_refused";
	case ZAPI_MVPN_SG_FWD_REASON_UNSPECIFIED:
	default:
		return "unknown";
	}
}

/*
 * Build the shared part of a forwarding record.
 *
 * The record deliberately reuses the CURRENT route_version rather than
 * minting a new generation: a readiness record is not a producer lifecycle
 * transition, it annotates the entitlement interval that contains it, and it
 * must be joinable to that interval by (source, group, route_version).
 * Bumping the generation here would tell every settlement consumer that the
 * entitlement window closed and reopened, which is exactly the over-claim /
 * under-claim hazard D4 exists to avoid.
 *
 * It does advance `seq`, because it is a real record on the stream and the
 * consumer cursor must stay contiguous across it -- that contiguity is what
 * the ignore-and-advance rule in doc/mvpn-events-schema.md depends on.
 */
static struct json_object *bgp_mvpn_event_forwarding_new(struct bgp_mvpn_event_sink *sink,
							 struct bgp_mvpn_event_join *join,
							 const char *event_type)
{
	struct json_object *jo;
	char route_version[32], lc_umh_origin[48];

	bgp_mvpn_event_route_version(route_version, sizeof(route_version), sink->boot_epoch,
				     join->generation);
	bgp_mvpn_event_lc_umh_origin(lc_umh_origin, sizeof(lc_umh_origin), join->last_source_as,
				     join->last_umh);

	jo = bgp_mvpn_event_new(sink, event_type, &join->src, &join->grp, join->last_source_as,
				route_version);
	if (!jo)
		return NULL;

	if (lc_umh_origin[0])
		json_object_string_add(jo, "lc_umh_origin", lc_umh_origin);
	if (join->last_umh.s_addr != INADDR_ANY) {
		char umhbuf[INET_ADDRSTRLEN];

		json_object_string_add(jo, "upstream_peer",
				       inet_ntop(AF_INET, &join->last_umh, umhbuf, sizeof(umhbuf)));
	}

	return jo;
}

/*
 * Close the open readiness interval for `join`, if there is one.
 *
 * Returns without emitting when no forwarding_ready was emitted for the
 * current route-state interval -- D3 "Failed": a path that never reported
 * ready has no readiness interval to close, and emitting an unpaired
 * forwarding_lost would invent one.  That guard is also what makes the
 * "exactly one forwarding_lost" cardinality hold: the latch is cleared here,
 * so a second call is a no-op.
 *
 * Never emits during snapshot replay: forwarding state is not part of the
 * snapshot (D4 restart matrix), and a replay must not fabricate a readiness
 * transition that did not happen.
 */
static void bgp_mvpn_event_forwarding_lost(struct bgp_mvpn_event_sink *sink,
					   struct bgp_mvpn_event_join *join, const char *reason)
{
	struct json_object *jo;
	struct json_object *jfwd;

	if (!join->forwarding_ready || sink->snapshot_replay_active)
		return;

	/* Clear the latch before the fallible allocation below.  If the record
	 * is lost, the reserved cursor gap is the signal; what must not happen
	 * is the latch staying set and a second forwarding_lost being emitted
	 * later for the same interval. */
	join->forwarding_ready = false;

	jo = bgp_mvpn_event_forwarding_new(sink, join, "forwarding_lost");
	if (!jo)
		return;

	jfwd = json_object_new_object();
	if (jfwd) {
		json_object_string_add(jfwd, "state", "lost");
		json_object_string_add(jfwd, "reason", reason);
		json_object_object_add(jo, "forwarding", jfwd);
	}

	bgp_mvpn_event_broadcast(sink, jo);
}

void bgp_mvpn_event_forwarding_update(struct bgp *bgp, const struct ipaddr *src,
				      const struct ipaddr *grp, uint8_t forwarding,
				      uint8_t fwd_reason, ifindex_t fwd_ifindex,
				      const char *fwd_oif)
{
	struct bgp_mvpn_event_sink *sink = bgp->mvpn_event_sink;
	struct bgp_mvpn_event_join *join;
	struct json_object *jo;
	struct json_object *jfwd;
	bool ready = forwarding == ZAPI_MVPN_SG_FWD_READY;

	if (!sink)
		return;
	/* Forwarding state is not in the snapshot; a replay never synthesises
	 * a readiness edge. */
	if (sink->snapshot_replay_active)
		return;

	/* Only a join this sink has seen installed can carry readiness: the
	 * readiness interval lives inside an entitlement interval, so with no
	 * open entitlement there is nothing to annotate.  Note this uses
	 * _find, not _get: readiness for an (S,G) we never installed must not
	 * conjure join state. */
	join = bgp_mvpn_event_join_find(sink, src, grp);
	if (!join || !join->installed)
		return;

	if (!ready) {
		bgp_mvpn_event_forwarding_lost(sink, join,
					       bgp_mvpn_event_fwd_reason_str(fwd_reason));
		return;
	}

	/* Edge-triggered: pimd re-ADDs on every event that could plausibly
	 * have moved readiness, so a level-triggered emitter would emit a
	 * duplicate forwarding_ready per redundant re-announce and break the
	 * contract's exactly-once cardinality. */
	if (join->forwarding_ready)
		return;

	join->forwarding_ready = true;

	jo = bgp_mvpn_event_forwarding_new(sink, join, "forwarding_ready");
	if (!jo)
		return;

	jfwd = json_object_new_object();
	if (jfwd) {
		json_object_string_add(jfwd, "state", "ready");
		/* The proven oif, resolved by pimd -- bgpd has no view of the
		 * DIMT netdev.  Emitted only when pimd actually named one, so
		 * a mixed-version peer that predates the field produces a
		 * record without it rather than a record claiming ifindex 0. */
		if (fwd_oif && fwd_oif[0]) {
			json_object_string_add(jfwd, "oif", fwd_oif);
			json_object_int_add(jfwd, "ifindex", (int64_t)fwd_ifindex);
		}
		/* The two ack names are constants, not observations: READY is
		 * defined as both acks having happened, so naming them records
		 * WHICH proof was required rather than re-asserting it. */
		json_object_string_add(jfwd, "tunnel_ack", "netlink");
		json_object_string_add(jfwd, "mfc_ack", "MRT_ADD_MFC");
		json_object_object_add(jo, "forwarding", jfwd);
	}

	bgp_mvpn_event_broadcast(sink, jo);
}

static struct bgp_mvpn_event_leaf *bgp_mvpn_event_leaf_find(struct bgp_mvpn_event_sink *sink,
							    const struct ipaddr *src,
							    const struct ipaddr *grp,
							    const struct ipaddr *leaf)
{
	struct bgp_mvpn_event_leaf *entry;

	for (entry = sink->leaves; entry; entry = entry->next)
		if (ipaddr_cmp(&entry->src, src) == 0 && ipaddr_cmp(&entry->grp, grp) == 0 &&
		    ipaddr_cmp(&entry->leaf, leaf) == 0)
			return entry;
	return NULL;
}

static struct bgp_mvpn_event_leaf *bgp_mvpn_event_leaf_get(struct bgp_mvpn_event_sink *sink,
							   const struct ipaddr *src,
							   const struct ipaddr *grp,
							   const struct ipaddr *leaf)
{
	struct bgp_mvpn_event_leaf *entry = bgp_mvpn_event_leaf_find(sink, src, grp, leaf);

	if (entry)
		return entry;

	entry = XCALLOC(MTYPE_MVPN_EVENT_LEAF, sizeof(*entry));
	entry->src = *src;
	entry->grp = *grp;
	entry->leaf = *leaf;
	entry->next = sink->leaves;
	sink->leaves = entry;
	return entry;
}

/*
 * Emit one leaf lifecycle event.
 *
 * The leaf carries its OWN route_version generation, independent of the
 * (C-S, C-G) join's. A leaf joining or leaving does not change the join's
 * upstream origin, and bumping the join's generation for it would tell every
 * other leaf's settlement window to close for no reason.
 */
static void bgp_mvpn_event_leaf_emit(struct bgp_mvpn_event_sink *sink,
				     struct bgp_mvpn_event_leaf *entry, const char *event_type)
{
	struct json_object *jo;
	char route_version[32], leafbuf[INET6_ADDRSTRLEN];
	uint32_t next_generation;

	/* A snapshot restates current state to one subscriber; it is not a
	 * producer transition and must not mint a new route_version. Mirrors
	 * bgp_mvpn_event_join_resolved(). */
	next_generation = sink->snapshot_replay_active && entry->installed ? entry->generation
									  : entry->generation + 1;
	bgp_mvpn_event_route_version(route_version, sizeof(route_version), sink->boot_epoch,
				     next_generation);

	jo = bgp_mvpn_event_new(sink, event_type, &entry->src, &entry->grp, 0, route_version);
	if (jo) {
		json_object_int_add(jo, "route_type", BGP_MVPN_ROUTE_TYPE_LEAF_AD);
		json_object_string_add(jo, "leaf",
				       ipaddr2str(&entry->leaf, leafbuf, sizeof(leafbuf)));
	}

	entry->generation = next_generation;

	if (jo) {
		if (sink->snapshot_replay_active)
			(void)bgp_mvpn_event_deliver(sink, sink->snapshot_client, jo);
		else
			bgp_mvpn_event_broadcast(sink, jo);
	}
}

/*
 * Reconcile the emitted leaf set against the Type-4 (Leaf A-D) routes actually
 * in the MVPN RIB, emitting leaf_install / leaf_withdraw for the difference.
 *
 * Only routes learned from a peer count. Our own Type-4 (originated by
 * bgp_mvpn_leaf_from_type3_set) carries bgp->router_id as leaf_originator --
 * this router advertising ITSELF as a leaf to the upstream PE. Billing that
 * would invoice the root for its own delivery.
 *
 * Type-4 routes exist only where a received Type-3 S-PMSI asked for them
 * (ingress replication with LEAF_INFO_REQUIRED, see
 * bgp_mvpn_type3_leaf_required). Outside that, there is no leaf set in BGP and
 * this walk correctly emits nothing.
 */
void bgp_mvpn_events_reconcile_leaves(struct bgp *bgp)
{
	struct bgp_mvpn_event_sink *sink = bgp->mvpn_event_sink;
	struct bgp_mvpn_event_leaf *entry, *next, **link;
	afi_t afi;

	if (!sink)
		return;
	if (sink->snapshot_replay_active &&
	    (!sink->snapshot_client || sink->snapshot_delivery_failed))
		return;

	for (entry = sink->leaves; entry; entry = entry->next)
		entry->seen = false;

	for (afi = AFI_IP; afi <= AFI_IP6; afi++) {
		struct bgp_table *table = bgp->rib[afi][SAFI_MCAST_VPN];
		struct bgp_dest *dest;

		if (!table)
			continue;

		for (dest = bgp_table_top(table); dest; dest = bgp_route_next(dest)) {
			const struct prefix *pfx = bgp_dest_get_prefix(dest);
			const struct mvpn_addr *m = &pfx->u.prefix_mvpn;
			struct bgp_path_info *pi;
			bool from_peer = false;

			if (pfx->family != AF_MVPN ||
			    m->route_type != BGP_MVPN_ROUTE_TYPE_LEAF_AD)
				continue;

			/* Valid AND selected, not merely "not removed".
			 *
			 * A Type-4 can sit in the RIB while being none of the
			 * things that make it real: rejected by inbound policy,
			 * invalidated by an unreachable next hop, or kept as a
			 * non-selected alternate alongside a better path. Billing
			 * any of those invents a leaf that is not installed.
			 *
			 * This is also what the post-best-path trigger already
			 * assumes. Reconciling after selection and then ignoring
			 * the selection flags contradicted the reason for hooking
			 * there at all. */
			for (pi = bgp_dest_get_bgp_path_info(dest); pi; pi = pi->next)
				if (pi->peer != bgp->peer_self &&
				    !CHECK_FLAG(pi->flags, BGP_PATH_REMOVED) &&
				    CHECK_FLAG(pi->flags, BGP_PATH_VALID) &&
				    CHECK_FLAG(pi->flags, BGP_PATH_SELECTED)) {
					from_peer = true;
					break;
				}
			if (!from_peer)
				continue;

			entry = bgp_mvpn_event_leaf_get(sink, &m->src, &m->grp,
							&m->leaf_originator);
			entry->seen = true;
			if (!entry->installed || sink->snapshot_replay_active) {
				bgp_mvpn_event_leaf_emit(sink, entry, "leaf_install");
				entry->installed = true;
			}
		}
	}

	/* A snapshot restates what is present; it must not withdraw. */
	if (sink->snapshot_replay_active)
		return;

	link = &sink->leaves;
	for (entry = *link; entry; entry = next) {
		next = entry->next;
		if (entry->seen) {
			link = &entry->next;
			continue;
		}
		if (entry->installed)
			bgp_mvpn_event_leaf_emit(sink, entry, "leaf_withdraw");
		*link = next;
		XFREE(MTYPE_MVPN_EVENT_LEAF, entry);
	}
}

static void bgp_mvpn_events_leaf_reconcile_event(struct event *event)
{
	struct bgp_mvpn_event_sink *sink = EVENT_ARG(event);

	bgp_mvpn_events_reconcile_leaves(sink->bgp);
}

/*
 * Request a leaf reconcile, coalescing a burst into one walk.
 *
 * The reconcile is a full scan of both MVPN RIBs. Running it inline on every
 * selected MCAST-VPN route made a burst of N arriving leaves do N full scans --
 * O(N^2) on bgpd's main route-processing path, and worst exactly where per-leaf
 * settlement is wanted, since needing it means having many leaves. Deferring to
 * the event loop collapses a convergence burst into a single walk once the
 * batch has settled.
 *
 * event_add_event() is a no-op while t_leaf_reconcile is already pending, so
 * the coalescing is the scheduling primitive rather than a hand-rolled flag.
 * Correctness does not depend on how many triggers collapse: the walk derives
 * state from the RIB rather than from any one update, so one walk after N
 * changes emits exactly what N walks would have.
 */
void bgp_mvpn_events_schedule_leaf_reconcile(struct bgp *bgp)
{
	struct bgp_mvpn_event_sink *sink = bgp->mvpn_event_sink;

	if (!sink)
		return;
	event_add_event(bm->master, bgp_mvpn_events_leaf_reconcile_event, sink, 0,
			&sink->t_leaf_reconcile);
}
