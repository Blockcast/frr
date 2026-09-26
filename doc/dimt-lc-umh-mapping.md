# LC-UMH to DIMT UMH mapping

Status: spec, no code yet. Implements step 1 of BLO-36558; the shared decoder
(step 2) and the neighbor-trust gate (step 3) follow and are blocked on
BLO-36553.

## Why this exists

The DIMT Upstream Multicast Hop has two on-the-wire encodings:

- the **UMH extended community**, experimental sub-type `0x80`
  (`ECOMMUNITY_UMH`), decoded by `bgp_dimt_umh_from_path()` in
  `bgpd/bgp_dimt.c`;
- the **UMH large community** (RFC 8092, RFC 8195 layout), decoded by
  `bgp_mvpn_resolve_from_lcommunity()` in `bgpd/bgp_mvpn.c:1232` and gated by
  `bgp mvpn umh-large-community <function>`.

Today only the MVPN Type-7 lane reads the large community. The DIMT pin path
reads the extended community only. That gap is not academic: **Arista can
originate a UMH only as a large community.** cEOS will carry and propagate the
`0x80` extended community but cannot originate one. Across the SFMIX Arista
route servers, a UMH that a carrier can actually set is an LC-UMH, so the DIMT
pin path sees nothing.

This document fixes the field-by-field mapping so the shared decoder has a
contract rather than an inference. **It is not a copy of the extended-community
decoder**: the LC encoding is IPv4-only and carries the PE address and nothing
else — no type field, no preference field.

## The two encodings side by side

### UMH extended community, IPv4 (8 bytes, `attr->ecommunity`)

| byte | meaning |
| --- | --- |
| 0 | `0x01` — `ECOMMUNITY_ENCODE_IP` |
| 1 | `0x80` — `ECOMMUNITY_UMH` |
| 2-5 | UMH IPv4 address (Global Administrator) |
| 6 | Local Administrator high byte — unused, not checked (forward compat) |
| 7 | Local Administrator low byte: `pref = b >> 4`, `type = b & 0x0f` |

### UMH extended community, IPv6 (20 bytes, `attr->ipv6_ecommunity`)

Same shape, `[0] = 0x00`, address at `[2..17]`, LA byte at `[19]`.

### UMH large community (12 bytes, `attr->lcommunity`)

| bytes | field | meaning |
| --- | --- | --- |
| 0-3 | Global Administrator | Source AS. Must equal the route's origin AS. |
| 4-7 | Function | local code point, set per lane (see the DIMT knob below); `0`/unset disables that lane's decode |
| 8-11 | Parameter | UMH IPv4 address as a host-order `uint32` |

There is no third u32 left over. **The LC has no room for a type or a
preference**, and a 16-byte IPv6 address has no representation in a u32
parameter. Both facts drive the mapping below.

## The mapping

### The DIMT lane has its own knob

`bgp mvpn umh-large-community <function>` sets `bgp->mvpn_umh_lc_function`,
which the MVPN decoder reads directly (`bgp_mvpn.c:1244`, `:1334`). The DIMT
lane does **not** reuse it. It gets its own knob,
`bgp dimt umh-large-community <function>`, stored in a separate `bgp` field
with `0`/unset disabling DIMT LC decode, and "the knob" below means that one:

- reusing the MVPN knob would make an operator who enables LC-UMH for MVPN
  silently enable LC decode on the DIMT pin path as well, the lane BLO-36553
  exists to gate. DIMT LC decode is its own opt-in;
- a DIMT-only deployment should not need an `mvpn`-namespaced command;
- the two lanes decode different objects from `Parameter`: MVPN turns it into
  the upstream PE's Route Target, DIMT into a PIM Light tunnel endpoint (see
  the comment on `bgp_mvpn_resolve_attested_umh()`). A deployment that wants
  one LC to feed both lanes sets both knobs to the same value.

So the shared decoder takes the function code point as an argument and reads
neither field itself; each call site passes its own lane's knob, the same
ownership rule as the family gate below. Changing the DIMT knob re-evaluates
the DIMT mapping of every IPv4 unicast route, as the MVPN knob re-resolves its
joins.

### Address — direct

`Parameter` is an IPv4 address in host byte order. `htonl()` it into a
`struct in_addr`, then `SET_IPADDR_V4()` on the `struct ipaddr` the zapi relay
carries. This is exactly what `bgp_mvpn_resolve_from_lcommunity()` already does
(`umh.s_addr = htonl(param)`); the known-answer vector `184549374 ==
10.255.255.254` in `bgp_mvpn_gtm_umh_lc` pins the endianness and must be reused.

### Type — default to `ZAPI_UMH_TYPE_PIM` (1)

The LC expresses no type. The default is PIM, not AMT relay, because:

- DIMT `-00` describes the UMH as the target of a PIM (Light) join. PIM is what
  the encoding is *for*;
- `ZAPI_UMH_TYPE_AMT_RELAY` (2) is the Blockcast-side extension. No vendor
  originates it, and an Arista or Junos box emitting an LC-UMH cannot possibly
  be asserting "AMT relay";
- it fails safe. Mistaking an AMT relay for a PIM neighbor produces a join that
  does not establish, which is visible. The reverse would hand multicast to an
  AMT relay that was never advertised as one.

An LC-UMH therefore **cannot** name an AMT relay. If that is ever needed the
carrier must use the extended community (which still wins with the knob set,
see the AMT-relay exception below), or DIMT must define a second function
code point — do not overload `Parameter`.

### Preference — default to `0`, and it is not a tiebreaker

The LC expresses no preference, so the decoder reports `0`. `0` is a real
encodable preference in the EC (`pref = b >> 4`, range 0-15), not a sentinel;
reporting it means "this source expressed none", which is honest and matches
what an EC carrying `pref 0` means.

Preference does **not** decide LC-vs-EC. That precedence is a separate rule:

> **When the knob is set, a valid LC-UMH wins over any UMH extended community
> on the same route, except when the tuple the EC list selects (highest
> `la_pref`) is typed `ZAPI_UMH_TYPE_AMT_RELAY`: then the EC wins. The extended
> community is otherwise the fallback, used whenever no valid LC tuple is
> present, and is the only encoding when the knob is unset.**

The exception exists because the LC's PIM type is a default, not an assertion,
while an EC typed AMT relay is an explicit one, and pimd honours it by not
pinning: it records and displays an amt-relay mapping but never pins on it
(`pim_dimt.c`, "Only pim-type mappings drive joins", pinned by
`tests/topotests/pim_dimt_umh/`). Letting the LC win would turn that no-pin
into a PIM Light join toward an AMT relay the moment the knob is set. A
PIM-typed EC makes no claim the LC contradicts, so it still loses.

The order otherwise mirrors the MVPN lane
(`bgp_mvpn_resolve_from_source_route()` tries LC first and falls back to EC).
The exception has no MVPN counterpart: the MVPN fallback is the RFC 6514 VRF
Route Import EC, which carries no type. Carry over the MVPN lane's
`debug bgp zebra` disagreement log, but compare what `0x80` actually carries,
the address **and the type** (the MVPN log compares Source AS and address
only). An LC overridden by an AMT-typed EC is logged even when both name the
same address.

Within the LC list, selection stays **lowest tuple wins** — large communities
are sorted and de-duplicated at attribute parse (`lcommunity_uniq_sort`), so
ascending iteration makes the winner deterministic. Note this is the opposite
of the EC list's **highest `la_pref` wins**; the two lists are selected
independently and neither rule leaks into the other.

### IPv6 — the LC lane is IPv4-only, and for DIMT that means AFI_IP only

Two separate restrictions, and they are not the same one:

1. **The UMH itself is always IPv4.** A u32 parameter cannot hold an IPv6
   address. An IPv6 UMH can only ever arrive as the 20-byte extended
   community. There is no LC encoding to add here without a new function code
   point, and this spec does not define one.

2. **For DIMT, the covering route must be IPv4 too.** This is where DIMT
   diverges from MVPN and it is the divergence most likely to be got wrong.

   MVPN accepts a v4 UMH on a v6 C-S route — test vector `p6` in
   `bgp_mvpn_gtm_umh_lc` does exactly that — because the MVPN core is v4 and
   the upstream PE is a v4 identity regardless of the C-S family (RFC 6515).

   DIMT is not that. `bgp_dimt_route_update()` is deliberately same-family: a
   v4 route yields a v4 UMH, a v6 route yields a v6 UMH, and a cross-family UMH
   EC is ignored with an explicit `zlog_warn`. The UMH here is a tunnel
   endpoint that pimd or pim6d must actually build a PIM Light adjacency to,
   not an identity in a v4 core.

   So the DIMT LC decode runs for `AFI_IP` only. An LC-UMH on a v6 unicast
   route is ignored, and it reuses the existing cross-family warn wording so
   the operator sees why a "configured" UMH never mapped.

   **The MVPN lane keeps `p6` working unchanged.** The shared decoder must not
   impose the DIMT family rule on the MVPN caller — the family gate belongs to
   the DIMT call site, not to the decoder.

### Trust — same rules as the DIMT UMH extended community

The LC lane must carry **both** gates, not just the one it has today:

- **Origin-AS**, which `bgp_mvpn_resolve_from_lcommunity()` already implements
  and which the shared decoder inherits as-is: reject when the AS_PATH bears an
  AS_SET, carries AS 0, or resolves to a confederation member; reject when
  `GA == 0` or `GA != origin_as`; substitute the local AS only when the AS_PATH
  is structurally empty and the peer is self or iBGP.
- **Per-neighbor DIMT trust**, the knob BLO-36553 is adding for the extended
  community.

The second is the security-load-bearing one. **Wiring the LC into the DIMT pin
path before the neighbor-trust gate exists would open exactly the hole
BLO-36553 is closing**, and hand any route-server peer a bypass around it: the
same route, refused as an EC, accepted as an LC. The parent epic's sequencing
rule — E2 lands before on-demand rows run on an IX-connected box — applies to
this lane for the same reason. Hence the blocker.

Usable-address rejects are unchanged and stay per-route (`0/8`, `127/8`,
`169.254/16`, `224/4`, `240/4` including `255.255.255.255`). Deliberately not
`ipv4_unicast_valid()`, which treats Class E as usable and gates `0/8` and
`127/8` on `allow-reserved-ranges` — neither is acceptable for an address an
adversary can put on the wire.

### Reject counter

The LC lane today has only a once-a-minute throttled `zlog_notice`, which is
not countable. Add a per-instance counter **per lane**, incremented on every
rejected tuple and readable from `show bgp` with the lane named, keeping the
throttled log for detail. The shared decoder owns no counter: it returns why it
rejected a tuple and the call site counts into its own lane's counter.
Otherwise the four reasons below that the decoder raises for both lanes would
land in one number with no attribution on an instance running both. Counted:
origin-ambiguous, `GA == 0`, `GA != origin_as`, unusable UMH address, and (for
the DIMT call site) wrong address family. A wrong `Function` is **not** a
reject — it is an unrelated large community and must not be counted, or every
route carrying any other LC inflates the number.

## Test obligations

- LC-only path pins the DIMT UMH, with no EC present on the route.
- Malformed / untrusted LC is rejected **and counted on the DIMT lane's
  counter**: GA mismatch, unusable address, and untrusted neighbor each move
  the DIMT counter, while the MVPN counter, with the MVPN knob unset, stays `0`.
- With the knob set, a v4 route carrying a valid LC-UMH and a `0x80` EC whose
  selected tuple is `amt-relay` maps as `amt-relay` from the EC and does not
  pin; the same route with a `pim` EC maps from the LC.
- Setting only `bgp mvpn umh-large-community` leaves the DIMT lane EC-only, and
  setting only `bgp dimt umh-large-community` leaves MVPN Type-7 resolution
  unchanged.
- `p6` and every other vector in `bgp_mvpn_gtm_umh_lc` stays green — the MVPN
  lane's v4-UMH-on-v6-route behaviour must not regress.
- A v6 unicast route carrying an LC-UMH pins to nothing on the DIMT lane, and
  warns.
- Endianness known-answer vector `184549374 -> 10.255.255.254` reused verbatim.

## References

- `bgpd/bgp_mvpn.c:1232` — `bgp_mvpn_resolve_from_lcommunity()`, call site `:1578`
- `bgpd/bgp_dimt.c` — `bgp_dimt_umh_from_path()`, the `0x80` decoder
- `bgpd/bgp_ecommunity.h:83-87` — `ECOMMUNITY_UMH` and the LA nibble macros
- `lib/zclient.h:790` — `ZAPI_UMH_TYPE_PIM`, `ZAPI_UMH_TYPE_AMT_RELAY`
- `tests/topotests/bgp_mvpn_gtm_umh_lc/` — the 13 LC vectors
- BLO-36553 — neighbor-trust gate (blocker for the decoder)
- BLO-17630 — LC-UMH across the SFMIX Arista route servers
