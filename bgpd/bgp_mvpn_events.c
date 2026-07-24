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
 * frr_runstatedir and incremented on every listener start -- a bgpd restart
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

#include "bgpd/bgpd.h"
#include "bgpd/bgp_mvpn.h"
#include "bgpd/bgp_mvpn_events.h"

DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_SINK, "MVPN event sink");
DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_CLIENT, "MVPN event sink client");
DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_JOIN, "MVPN event join state");
DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_PATH, "MVPN event socket path");
DEFINE_MTYPE_STATIC(BGPD, MVPN_EVENT_LINE, "MVPN event wire line");

/* A slow/wedged reader is disconnected rather than buffered without bound --
 * an unbounded queue would turn a stalled consumer into unbounded bgpd
 * memory growth on a settlement-critical path. Disconnection is the gap
 * signal (see file header): the client's next connection restarts its read
 * at whatever seq is current, and the seq discontinuity is exactly what
 * tells it bytes were lost in between. */
#define BGP_MVPN_EVENT_SINK_MAX_BACKLOG (8 * 1024 * 1024)

struct bgp_mvpn_event_client {
	struct bgp_mvpn_event_client *next;
	int fd;
	struct buffer *wb;
	size_t pending_bytes; /* upper-bound accounting, see bgp_mvpn_event_broadcast() */
	struct event *t_read;
	struct event *t_write;
	struct bgp_mvpn_event_sink *sink; /* back-pointer for the write callback */
};

struct bgp_mvpn_event_join {
	struct bgp_mvpn_event_join *next;
	struct ipaddr src;
	struct ipaddr grp;
	uint32_t generation;
	bool installed;
	uint32_t last_source_as;
	struct in_addr last_umh;
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
	bool snapshot_pending;
};

static void bgp_mvpn_event_client_close(struct bgp_mvpn_event_sink *sink,
					struct bgp_mvpn_event_client *client)
{
	struct bgp_mvpn_event_client **pp;

	for (pp = &sink->clients; *pp; pp = &(*pp)->next)
		if (*pp == client) {
			*pp = client->next;
			break;
		}

	event_cancel(&client->t_read);
	event_cancel(&client->t_write);
	buffer_free(client->wb);
	close(client->fd);
	XFREE(MTYPE_MVPN_EVENT_CLIENT, client);
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
	if (status == BUFFER_EMPTY) {
		client->pending_bytes = 0;
		return;
	}
	event_add_write(bm->master, bgp_mvpn_event_client_write, client, client->fd,
			&client->t_write);
}

/* Read side exists only to notice the peer went away (POLLHUP/EOF); the
 * protocol is producer -> consumer only, so any inbound byte is ignored. */
static void bgp_mvpn_event_client_read(struct event *event)
{
	struct bgp_mvpn_event_client *client = EVENT_ARG(event);
	struct bgp_mvpn_event_sink *sink = client->sink;
	char scratch[256];
	ssize_t n;

	n = read(client->fd, scratch, sizeof(scratch));
	/* n == 0 is EOF, unconditionally: read() does not touch errno on a
	 * clean peer close, so gating it on a (stale) errno value would leave
	 * a dead client unreaped with its socket perpetually POLLIN-ready --
	 * a 100% CPU rearm loop. errno is only meaningful for n < 0. */
	if (n == 0 ||
	    (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)) {
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

	/* A listener restart closes every old client. The first consumer in the
	 * new epoch therefore receives a fresh install snapshot of all active
	 * local joins; later clients retain the normal no-replay semantics. */
	if (sink->snapshot_pending) {
		struct bgp_mvpn_event_join *join;

		sink->snapshot_pending = false;
		for (join = sink->joins; join; join = join->next)
			join->installed = false;
		bgp_mvpn_reemit_local_joins(sink->bgp);
	}
}

/*
 * The durable half of the cursor: a small text file under frr_runstatedir
 * holding the next boot_epoch to hand out, read-incremented-written under an
 * exclusive lock so two bgpd processes (or bgpd + a stray leftover) can never
 * be handed the same epoch. runstatedir is ephemeral across a host *reboot*
 * (may be tmpfs) but that is exactly the boundary this scheme needs: a bare
 * reboot restarts every downstream consumer too, so there is nothing for the
 * epoch to protect against there. A bare `bgpd` process restart -- the case
 * that matters -- always sees runstatedir intact.
 */
static uint64_t bgp_mvpn_event_next_boot_epoch(const char *instance_name)
{
	char path[512];
	int fd;
	uint64_t epoch = 1;
	char buf[32];
	ssize_t n;

	snprintf(path, sizeof(path), "%s/bgpd-mvpn-events-%s.epoch", frr_runstatedir,
		 (instance_name && instance_name[0]) ? instance_name : "default");

	fd = open(path, O_RDWR | O_CREAT, 0600);
	if (fd < 0) {
		flog_err(EC_LIB_SYSTEM_CALL,
			 "MVPN event boot_epoch file %s open failed: %s -- falling back to epoch 1 every restart",
			 path, safe_strerror(errno));
		return 1;
	}

	if (lockf(fd, F_LOCK, 0) < 0)
		flog_err(EC_LIB_SYSTEM_CALL, "MVPN event boot_epoch file %s lock failed: %s",
			 path, safe_strerror(errno));

	n = read(fd, buf, sizeof(buf) - 1);
	if (n > 0) {
		buf[n] = '\0';
		epoch = strtoull(buf, NULL, 10) + 1;
	}
	if (epoch == 0)
		epoch = 1;

	n = snprintf(buf, sizeof(buf), "%" PRIu64, epoch);
	if (ftruncate(fd, 0) < 0 || lseek(fd, 0, SEEK_SET) < 0 || write(fd, buf, n) != n ||
	    fsync(fd) < 0)
		flog_err(EC_LIB_SYSTEM_CALL,
			 "MVPN event boot_epoch file %s update failed: %s -- next restart may reuse an epoch",
			 path, safe_strerror(errno));

	close(fd); /* releases the lockf() lock */
	return epoch;
}

void bgp_mvpn_events_start(struct bgp *bgp)
{
	struct bgp_mvpn_event_sink *sink;
	struct sockaddr_un sun;
	mode_t old_mask;
	int fd;

	if (!bgp->mvpn_event_socket_path)
		return;
	if (bgp->mvpn_event_sink &&
	    strcmp(bgp->mvpn_event_sink->path, bgp->mvpn_event_socket_path) == 0)
		return; /* already running on the configured path */

	bgp_mvpn_events_stop(bgp);

	if (strlen(bgp->mvpn_event_socket_path) >= sizeof(sun.sun_path)) {
		flog_err(EC_LIB_SYSTEM_CALL, "MVPN event socket path %s too long",
			 bgp->mvpn_event_socket_path);
		return;
	}

	fd = socket(AF_UNIX, SOCK_STREAM, 0);
	if (fd < 0) {
		flog_err(EC_LIB_SOCKET, "MVPN event socket() failed: %s", safe_strerror(errno));
		return;
	}

	memset(&sun, 0, sizeof(sun));
	sun.sun_family = AF_UNIX;
	strlcpy(sun.sun_path, bgp->mvpn_event_socket_path, sizeof(sun.sun_path));
	unlink(sun.sun_path);

	old_mask = umask(0077);
	if (bind(fd, (struct sockaddr *)&sun, sizeof(sun)) < 0) {
		flog_err(EC_LIB_SOCKET, "MVPN event socket bind(%s) failed: %s", sun.sun_path,
			 safe_strerror(errno));
		umask(old_mask);
		close(fd);
		return;
	}
	umask(old_mask);

	if (listen(fd, 8) < 0) {
		flog_err(EC_LIB_SOCKET, "MVPN event socket listen(%s) failed: %s", sun.sun_path,
			 safe_strerror(errno));
		close(fd);
		return;
	}

	if (set_nonblocking(fd) < 0) {
		flog_err(EC_LIB_SOCKET,
			 "MVPN event socket: set_nonblocking(%s) failed: %s",
			 sun.sun_path, safe_strerror(errno));
		unlink(sun.sun_path);
		close(fd);
		return;
	}

	sink = XCALLOC(MTYPE_MVPN_EVENT_SINK, sizeof(*sink));
	sink->bgp = bgp;
	sink->path = XSTRDUP(MTYPE_MVPN_EVENT_PATH, bgp->mvpn_event_socket_path);
	sink->listen_fd = fd;
	sink->boot_epoch = bgp_mvpn_event_next_boot_epoch(bgp->name ? bgp->name
								    : VRF_DEFAULT_NAME);
	sink->seq = 0;
	sink->snapshot_pending = true;
	bgp->mvpn_event_sink = sink;

	event_add_read(bm->master, bgp_mvpn_event_accept, sink, fd, &sink->t_accept);

	zlog_info("MVPN events: listening on %s (boot_epoch %" PRIu64 ")", sun.sun_path,
		  sink->boot_epoch);
}

void bgp_mvpn_events_stop(struct bgp *bgp)
{
	struct bgp_mvpn_event_sink *sink = bgp->mvpn_event_sink;
	struct bgp_mvpn_event_join *join;

	if (!sink)
		return;

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

	XFREE(MTYPE_MVPN_EVENT_PATH, sink->path);
	XFREE(MTYPE_MVPN_EVENT_SINK, sink);
	bgp->mvpn_event_sink = NULL;
}

void bgp_mvpn_events_set_socket(struct bgp *bgp, const char *path)
{
	XFREE(MTYPE_MVPN_EVENT_PATH, bgp->mvpn_event_socket_path);

	if (!path) {
		bgp_mvpn_events_stop(bgp);
		return;
	}

	bgp->mvpn_event_socket_path = XSTRDUP(MTYPE_MVPN_EVENT_PATH, path);
	bgp_mvpn_events_start(bgp);
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
	int clients = 0;

	if (sink)
		for (client = sink->clients; client; client = client->next)
			clients++;

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

static void bgp_mvpn_event_broadcast(struct bgp_mvpn_event_sink *sink, struct json_object *jo)
{
	const char *text;
	char *line;
	size_t textlen, linelen;
	struct bgp_mvpn_event_client *client, *next;

	text = json_object_to_json_string_ext(jo, JSON_C_TO_STRING_PLAIN);
	textlen = strlen(text);
	linelen = textlen + 1;
	line = XMALLOC(MTYPE_MVPN_EVENT_LINE, linelen);
	memcpy(line, text, textlen);
	line[textlen] = '\n';

	for (client = sink->clients; client; client = next) {
		buffer_status_t status;

		next = client->next;

		if (client->pending_bytes + linelen > BGP_MVPN_EVENT_SINK_MAX_BACKLOG) {
			zlog_warn("MVPN events: client fd %d exceeded %u byte backlog, disconnecting (gap signal for reconnect)",
				  client->fd, BGP_MVPN_EVENT_SINK_MAX_BACKLOG);
			bgp_mvpn_event_client_close(sink, client);
			continue;
		}

		status = buffer_write(client->wb, client->fd, line, linelen);
		if (status == BUFFER_ERROR) {
			bgp_mvpn_event_client_close(sink, client);
			continue;
		}
		if (status == BUFFER_EMPTY) {
			client->pending_bytes = 0;
			continue;
		}

		client->pending_bytes += linelen;
		if (!client->t_write)
			event_add_write(bm->master, bgp_mvpn_event_client_write, client,
					client->fd, &client->t_write);
	}

	XFREE(MTYPE_MVPN_EVENT_LINE, line);
	json_object_free(jo);
}

static struct json_object *bgp_mvpn_event_new(struct bgp_mvpn_event_sink *sink,
					      const char *event_type, const struct ipaddr *src,
					      const struct ipaddr *grp, uint32_t source_as,
					      const char *route_version)
{
	struct json_object *jo;
	struct timespec ts;
	char srcbuf[INET6_ADDRSTRLEN], grpbuf[INET6_ADDRSTRLEN];

	/* Reserve the cursor before json-c's fallible allocation. If allocation
	 * fails, the next successful event exposes the missing sequence instead
	 * of silently losing a settlement transition. */
	sink->seq++;
	jo = json_object_new_object();
	if (!jo) {
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

	join = bgp_mvpn_event_join_get(sink, src, grp);
	is_new = !join->installed;
	changed = !is_new &&
		  (join->last_source_as != source_as || join->last_umh.s_addr != umh.s_addr);

	if (!is_new && !changed)
		return; /* redundant re-resolve: same origin as last emitted */

	if (!is_new)
		bgp_mvpn_event_route_version(prior_route_version, sizeof(prior_route_version),
					     sink->boot_epoch, join->generation);

	next_generation = join->generation + 1;
	bgp_mvpn_event_route_version(route_version, sizeof(route_version), sink->boot_epoch,
				     next_generation);
	bgp_mvpn_event_lc_umh_origin(lc_umh_origin, sizeof(lc_umh_origin), source_as, umh);

	jo = bgp_mvpn_event_new(sink, is_new ? "install" : "origin_change", src, grp, source_as,
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

	if (jo)
		bgp_mvpn_event_broadcast(sink, jo);
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
