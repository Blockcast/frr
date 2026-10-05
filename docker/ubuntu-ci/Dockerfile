ARG UBUNTU_VERSION=22.04

# ccache seed for the compile steps below. Empty by default, so a plain
# `docker build` is the cold path and needs nothing injected. CI overrides it
# with `--build-context ccache-seed=<dir>` pointing at the ccache directory
# actions/cache restored (see "Restore ccache" in github-ci.yml).
FROM scratch AS ccache-seed

# `--target ccache-out --output type=local,dest=<dir>` exports the compile
# steps' ccache after a build on the same builder, for actions/cache to save.
# A cache mount is never part of an image or of the registry buildcache, so a
# second build that reads the mount by its id is the only way out of the
# builder. FRR_SOURCE_REV only keeps this RUN from being cached on a builder
# that already exported once.
FROM ubuntu:$UBUNTU_VERSION AS ccache-export
ARG FRR_SOURCE_REV=unknown
RUN --mount=type=cache,id=frr-ccache,target=/ccache,uid=1010,gid=92,sharing=locked \
    echo "Exporting ccache for ${FRR_SOURCE_REV}" && cp -a /ccache /ccache-out
FROM scratch AS ccache-out
COPY --from=ccache-export /ccache-out/ /

FROM ubuntu:$UBUNTU_VERSION

# If passed, update the value
ARG UBUNTU_VERSION
ARG DEBIAN_FRONTEND=noninteractive

# Number of retries for transient network failures
ARG APT_RETRIES=3

# Optional mirror for MIB downloads (expects mirrored https path layout).
ARG MIB_MIRROR_BASE_URL=

# Configure apt to retry on transient network failures
RUN echo "Acquire::Retries \"${APT_RETRIES}\";" > /etc/apt/apt.conf.d/80-retries && \
    echo 'Acquire::http::Timeout "30";' >> /etc/apt/apt.conf.d/80-retries && \
    echo 'Acquire::https::Timeout "30";' >> /etc/apt/apt.conf.d/80-retries

# Update and install build requirements.
# Retry loop for apt-get update/upgrade/install in case of transient mirror failures
RUN for i in $(seq 1 ${APT_RETRIES}); do \
        apt-get update && \
        apt-get upgrade -y && \
    # Basic build requirements from documentation
    apt-get install -y \
            autoconf \
            automake \
            bison \
            build-essential \
            flex \
            git \
            install-info \
            libc-ares-dev \
            libcap-dev \
            libelf-dev \
            libjson-c-dev \
            libpam0g-dev \
            libreadline-dev \
            libsnmp-dev \
            libsqlite3-dev \
            lsb-release \
            libtool \
            lcov \
            make \
            perl \
            pkg-config \
            python3-dev \
            python3-sphinx \
            screen \
            texinfo \
            tmux \
            iptables \
    && \
    # Protobuf build requirements
    apt-get install -y \
        libprotobuf-c-dev \
        protobuf-c-compiler \
    && \
    # Libyang2 extra build requirements
    apt-get install -y \
        cmake \
        libpcre2-dev \
    && \
    # GRPC extra build requirements
    apt-get install -y \
        libgrpc-dev \
        libgrpc++-dev \
        protobuf-compiler-grpc \
    && \
    # Runtime/triage/testing requirements
    apt-get install -y \
        curl \
        gdb \
        kmod \
        iproute2 \
        iputils-ping \
        libcunit1-dev \
        liblua5.3-dev \
        libssl-dev \
        lua5.3 \
        net-tools \
        python3 \
        python3-pip \
        snmp \
	snmptrapd \
        snmp-mibs-downloader \
        snmpd \
        ssmping \
        # strace drives the zebra_dimt_tunnel netlink failure-injection and
        # dplane-hold topotests (strace -e inject=). Without it those tests
        # skip, and a skipped failure-injection test reads as green.
        #
        # This is the distro build and is NOT the one those tests run: a
        # pinned 6.8 source build lands in /usr/local/bin further down and
        # wins `command -v strace`. Kept because jammy's 5.16 is a fine
        # fallback for every other use, and removing it would make the source
        # build load-bearing for the whole image.
        strace \
        sudo \
        time \
        tshark \
        valgrind \
        yodl \
        && break || sleep 10; \
    done && \
    download-mibs && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://raw.githubusercontent.com/FRRouting/frr-mibs/main/iana/IANA-IPPM-METRICS-REGISTRY-MIB -O /usr/share/snmp/mibs/iana/IANA-IPPM-METRICS-REGISTRY-MIB && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/SNMPv2-PDU -O /usr/share/snmp/mibs/ietf/SNMPv2-PDU && \
    wget --tries=5 --waitretry=10 --retry-connrefused https://raw.githubusercontent.com/FRRouting/frr-mibs/main/ietf/IPATM-IPMC-MIB -O /usr/share/snmp/mibs/ietf/IPATM-IPMC-MIB && \
    rm -f /usr/lib/python3.*/EXTERNALLY-MANAGED && \
    python3 -m pip install wheel && \
    bash -c "PV=($(pkg-config --modversion protobuf | tr '.' ' ')); if (( PV[0] == 3 && PV[1] < 19 )); then python3 -m pip install 'protobuf<4' grpcio grpcio-tools; else python3 -m pip install 'protobuf>=4' grpcio grpcio-tools; fi" && \
    python3 -m pip install 'pytest>=6.2.4' 'pytest-xdist>=3.6.1' 'pytest-asyncio>=0.25.3' && \
    python3 -m pip install 'scapy>=2.4.5' && \
    python3 -m pip install pyyaml && \
    python3 -m pip install xmltodict && \
    python3 -m pip install git+https://github.com/Exa-Networks/exabgp@0659057837cd6c6351579e9f0fa47e9fb7de7311

COPY docker/ubuntu-ci/ /tmp/ubuntu-ci-assets/

RUN if [ "$UBUNTU_VERSION" = "24.04" ]; then \
        # Fetch with optional mirror fallback and exponential backoff.
        fetch_mib() { \
            src_url="$1"; \
            dest_path="$2"; \
            mirror_url=""; \
            cache_path="/tmp/ubuntu-ci-assets/mib-cache/$(basename "$dest_path")"; \
            if [ -s "$cache_path" ]; then \
                cp "$cache_path" "$dest_path" && return 0; \
            fi; \
            if [ -n "$MIB_MIRROR_BASE_URL" ]; then \
                mirror_url="${MIB_MIRROR_BASE_URL%/}/${src_url#https://}"; \
            fi; \
            attempt=1; \
            max_attempts=8; \
            while [ "$attempt" -le "$max_attempts" ]; do \
                if [ -n "$mirror_url" ]; then \
                    wget --tries=1 --timeout=30 --retry-connrefused "$mirror_url" -O "$dest_path" && return 0; \
                fi; \
                wget --tries=1 --timeout=30 --retry-connrefused "$src_url" -O "$dest_path" && return 0; \
                sleep_time=$((attempt * 5)); \
                echo "Retrying MIB fetch (${attempt}/${max_attempts}) for $src_url in ${sleep_time}s" >&2; \
                sleep "$sleep_time"; \
                attempt=$((attempt + 1)); \
            done; \
            echo "Failed to fetch $src_url after ${max_attempts} attempts" >&2; \
            return 1; \
        }; \
        fetch_mib https://www.iana.org/assignments/ianasmf-mib/ianasmf-mib /usr/share/snmp/mibs/iana/IANA-SMF-MIB && \
        fetch_mib https://www.iana.org/assignments/ianaentity-mib/ianaentity-mib /usr/share/snmp/mibs/iana/IANA-ENTITY-MIB && \
        fetch_mib https://www.iana.org/assignments/ianapowerstateset-mib/ianapowerstateset-mib /usr/share/snmp/mibs/iana/IANAPowerStateSet-MIB && \
        fetch_mib https://www.iana.org/assignments/ianaolsrv2linkmetrictype-mib/ianaolsrv2linkmetrictype-mib /usr/share/snmp/mibs/iana/IANA-OLSRv2-LINK-METRIC-TYPE-MIB && \
        fetch_mib https://www.iana.org/assignments/ianaenergyrelation-mib/ianaenergyrelation-mib /usr/share/snmp/mibs/iana/IANA-ENERGY-RELATION-MIB && \
        fetch_mib https://www.iana.org/assignments/ianabfdtcstd-mib/ianabfdtcstd-mib /usr/share/snmp/mibs/iana/IANA-BFD-TC-STD-MIB && \
        fetch_mib https://www.iana.org/assignments/ianastoragemediatype-mib/ianastoragemediatype-mib /usr/share/snmp/mibs/iana/IANA-STORAGE-MEDIA-TYPE-MIB && \
        fetch_mib https://www.ieee802.org/1/files/public/MIBs/IEEE8021-CFM-MIB.mib /usr/share/snmp/mibs/IEEE8021-CFM-MIB && \
        fetch_mib https://www.ieee802.org/1/files/public/MIBs/LLDP-MIB-200505060000Z.mib /usr/share/snmp/mibs/LLDP-MIB; \
    fi

ARG UID=1010
RUN groupadd -r -g 92 frr && \
      groupadd -r -g 85 frrvty && \
      adduser --system --ingroup frr --home /home/frr \
              --gecos "FRR suite" -u $UID --shell /bin/bash frr && \
      usermod -a -G frrvty frr && \
      useradd -d /var/run/exabgp/ -s /bin/false exabgp && \
      echo 'frr ALL = NOPASSWD: ALL' | tee /etc/sudoers.d/frr && \
      mkdir -p /home/frr && chown frr.frr /home/frr

# Install FRR built packages
# Retry loop for curl in case of transient network failures
RUN mkdir -p /etc/apt/keyrings && \
    for i in $(seq 1 ${APT_RETRIES}); do \
        curl -sf -o /etc/apt/keyrings/frrouting.gpg https://deb.frrouting.org/frr/keys.gpg && break || sleep 10; \
    done && \
    echo deb '[signed-by=/etc/apt/keyrings/frrouting.gpg]' https://deb.frrouting.org/frr \
        $(lsb_release -s -c) "frr-stable" > /etc/apt/sources.list.d/frr.list && \
    for i in $(seq 1 ${APT_RETRIES}); do apt-get update && break || sleep 10; done && \
    apt-get install -y librtr-dev

# build and install libyang3
RUN cd && pwd && ls -al && \
    git clone https://github.com/CESNET/libyang.git && \
    cd libyang && \
    git checkout v3.13.6 && \
    mkdir build; cd build && \
    cmake -DCMAKE_INSTALL_PREFIX:PATH=/usr \
    -DCMAKE_BUILD_TYPE:String="Debug" .. && \
    make -j $(nproc) && \
    sudo make install
RUN python3 -m pip install 'libyang<4'

# strace >= 6.4 is required for `-e trace-fds=` to narrow failure injection to a
# socket fd: 6.3 added the option, 6.4 made it work for fds with no associated
# path -- i.e. sendmsg on a netlink socket. Jammy ships 5.16, whose
# qual_options[] has no fd qualifier at all, so it parses `-e trace-fds=15` as a
# syscall set and dies before attaching; the injection then never fires and the
# zebra_dimt_tunnel send-side tests go red (BLO-28405).
#
# Unconditional, and pinned to 6.8, so both UBUNTU_VERSION legs run a
# byte-identical tracer and cannot diverge on tracer behaviour. 6.8 is what
# noble already ships -- so u22 gets exactly the tracer u24 has today -- and is
# what this module's INJECTED/DELAYED tag behaviour was measured against
# (test_zebra_dimt_tunnel.py: "measured on strace 6.8").
#
# Installed to the default /usr/local prefix rather than /opt + $STRACE_BIN:
# topotests invoke strace through router.run() inside a netns, where env-var
# propagation is a live failure mode, and `command -v strace` resolving to the
# new binary needs no test-side change at all.
ARG STRACE_VERSION=6.8
ARG STRACE_SHA256=ba6950a96824cdf93a584fa04f0a733896d2a6bc5f0ad9ffe505d9b41e970149
RUN set -eux; \
    # Two sources so a single-host outage cannot stop every image build.
    # Both serve the byte-identical tarball (digest verified against the pin
    # below); the sha256sum -c is what makes a second source safe.
    curl -fsSL --retry 5 --retry-connrefused -o /tmp/strace.tar.xz \
      "https://strace.io/files/${STRACE_VERSION}/strace-${STRACE_VERSION}.tar.xz" \
    || curl -fsSL --retry 5 --retry-connrefused -o /tmp/strace.tar.xz \
      "https://github.com/strace/strace/releases/download/v${STRACE_VERSION}/strace-${STRACE_VERSION}.tar.xz"; \
    echo "${STRACE_SHA256}  /tmp/strace.tar.xz" | sha256sum -c -; \
    tar -C /tmp -xf /tmp/strace.tar.xz; \
    cd "/tmp/strace-${STRACE_VERSION}"; \
    # --enable-mpers=no drops the gcc-multilib dependency; nothing here traces
    # 32-bit personalities.
    ./configure --enable-mpers=no >/dev/null; \
    make -j"$(nproc)" >/dev/null; \
    make install; \
    cd /; rm -rf /tmp/strace*; \
    # Fail the image build in seconds, not a topotest 40 minutes later, if the
    # tracer cannot do the one thing it was upgraded for.
    strace -e trace-fds=1 -o /dev/null true

# ccache for the two FRR compile steps at the end, pinned and verified like
# strace above. Not the distro package: --enable-gcov compiles everything with
# -fprofile-update=atomic, which ccache only accepts from 4.10 on. jammy's
# 4.5.1 and noble's 4.9.1 log "Unknown profiling option" and run the compiler
# uncached, which on a 22.04 build was 1360 of ~1490 compiles. The
# musl-static build runs unchanged on both releases. Its own layer below
# every expensive one, so adding it did not invalidate the libyang and strace
# builds above.
#
# /usr/local/lib/ccache holds gcc/g++/cc/c++ links to it. Only `make` and
# `make check` below run with that directory first in PATH, so the image's
# Makefiles record plain `gcc` and never depend on ccache (Unit-Test re-runs
# `make check` from the image without it). configure runs without it: its
# few hundred one-off test compiles are uncacheable or never repeat, and
# through ccache they made configure 55 s slower on a 4-CPU builder (62 s ->
# 117 s), most of what the cache saved in `make`.
ARG CCACHE_VERSION=4.14.1
ARG CCACHE_SHA256_X86_64=fa1443c9fbea879c9bff6619d1284eda3102992e91831b9f6e546879972195cc
ARG CCACHE_SHA256_AARCH64=265d687c6d84a96cef851b57f804b21fc8268e53bfbc468441d029a5f7000a10
RUN set -eux; \
    arch="$(uname -m)"; \
    case "$arch" in \
      x86_64) sum="$CCACHE_SHA256_X86_64" ;; \
      aarch64) sum="$CCACHE_SHA256_AARCH64" ;; \
      *) echo "no pinned ccache for $arch" >&2; exit 1 ;; \
    esac; \
    pkg="ccache-${CCACHE_VERSION}-linux-${arch}-musl-static"; \
    curl -fsSL --retry 5 --retry-connrefused -o /tmp/ccache.tar.xz \
      "https://github.com/ccache/ccache/releases/download/v${CCACHE_VERSION}/${pkg}.tar.xz"; \
    echo "${sum}  /tmp/ccache.tar.xz" | sha256sum -c -; \
    tar -C /tmp -xf /tmp/ccache.tar.xz; \
    install -m 0755 "/tmp/${pkg}/ccache" /usr/local/bin/ccache; \
    rm -rf /tmp/ccache.tar.xz "/tmp/${pkg}"; \
    mkdir -p /usr/local/lib/ccache; \
    for c in gcc g++ cc c++; do ln -s ../../bin/ccache "/usr/local/lib/ccache/$c"; done; \
    ccache --version | head -1

# LTTng tracing dependencies (conditional).
#
# Deliberately the LAST root layer. ENABLE_LTTNG is a cache-key input for every
# instruction after the one that consumes it, so placing this earlier forked the
# layer chain for the two Ubuntu 24.04 legs ahead of the MIB fetch, the apt
# keyring setup and the pip installs -- and made those expensive layers
# unshareable between them. Keep any new conditional-on-ENABLE_LTTNG work below
# this line, not above it.
#
# The ARG is declared here, not at the top of the stage, for the same reason: a
# stage ARG is an implicit input to every RUN after its declaration, so declared
# right after FROM it forked the LTTng leg at the very first RUN and none of the
# layers above could be shared. This placement is the precondition, not the
# sharing itself: it shows up within one BuildKit cache, but each CI leg runs a
# fresh builder that reads only the -buildcache refs it names, so Build-LTTng in
# github-ci.yml names the amd64_u24 ref as a second cache-from.  The ARG stays
# in scope to the end of the stage (USER does not end it), so the configure step
# below sees it too -- and fails the build if it ever does not: a FROM inserted
# in between would otherwise drop --enable-lttng silently, and Build-LTTng would
# go on passing while building an image without LTTng.
ARG ENABLE_LTTNG=false
RUN if [ "$ENABLE_LTTNG" = "true" ]; then \
        apt-get install -y liblttng-ust-dev; \
    fi

USER frr:frr

# CI build arg used to invalidate the compile layer when source revision changes.
ARG FRR_SOURCE_REV=unknown

# ccache for the compile (`make`) and `make check` steps. FRR_SOURCE_REV
# rebuilds both on every commit by design, but most translation units do not
# change between two commits, so ccache turns their recompile into a cache read.
#
# The cache lives in a BuildKit cache mount, which is NOT exported with the
# image or the registry buildcache, and CI builders are fresh per job. CI
# carries it between runs with actions/cache: restored into the ccache-seed
# context (copied into the empty mount below), and exported via the
# ccache-out target after the build.
#
# Measured on a 4-CPU builder (22.04, master plus a one-line .c change, warm
# run and no-ccache run side by side): compile step 278 s vs 368 s, `make
# check` 234 s vs 281 s, 1148 of 1149 cacheable compiles hit. A miss costs
# more than no ccache at all (ccache preprocesses before it compiles): with no
# seed the compile step took 469 s. Master and buildcache-seed.yml runs save
# the cache, so a pull request starts from the newest master entry and pays
# that only for the files it changes; touching a header half the tree
# includes gets close to the cold number.
#
# These are ARGs, not ENVs, so they reach the RUNs below without landing in
# the image, which runs no compile through ccache (see the PATH note above).
#
# CCACHE_IGNOREOPTIONS: configure puts -DCONFDATE=<today> on every compile
# line of a -dev version (Makefile.am DEFS), which would make yesterday's
# cache miss on every file. Ignoring it is only safe in preprocessor mode
# (CCACHE_NODIRECT): the two files that test `#if CONFDATE > ...` then still
# hash differently once the date crosses their threshold, because the
# preprocessed output differs. Direct mode would serve the stale object.
#
# The cache that leaves the builder holds only what this build used: a hit
# refreshes an entry's mtime, so after `make check` everything older than the
# frr-build-start marker is a seed entry this commit no longer compiles, and
# is evicted. Without that, every master build would save the previous cache
# plus its own, growing each actions/cache entry toward CCACHE_MAXSIZE. The
# seed copy keeps its timestamps for the same reason: a plain cp -R would
# stamp every restored entry as new.
#
# Source and build dir are always /home/frr/frr, so the cache is path-stable
# without CCACHE_BASEDIR, and --coverage's .gcno files (which embed the cwd)
# stay correct.
ARG CCACHE_DIR=/home/frr/.ccache
ARG CCACHE_MAXSIZE=2G
ARG CCACHE_NODIRECT=1
ARG CCACHE_IGNOREOPTIONS=-DCONFDATE=*

COPY --chown=frr:frr . /home/frr/frr/

RUN --mount=type=cache,id=frr-ccache,target=/home/frr/.ccache,uid=1010,gid=92,sharing=locked \
    --mount=type=bind,from=ccache-seed,target=/tmp/ccache-seed \
    cd ~/frr && \
    echo "Building FRR source revision: ${FRR_SOURCE_REV}" && \
    if [ -z "$(ls -A "$CCACHE_DIR")" ] && [ -n "$(ls -A /tmp/ccache-seed)" ]; then \
        cp -R --preserve=timestamps /tmp/ccache-seed/. "$CCACHE_DIR"/; \
    fi && \
    touch "$CCACHE_DIR/frr-build-start" && \
    ccache -z && \
    ./bootstrap.sh && \
    LTTNG_OPT="" && \
    : "${ENABLE_LTTNG:?is not in scope: declare ARG ENABLE_LTTNG in this stage}" && \
    if [ "$ENABLE_LTTNG" = "true" ]; then LTTNG_OPT="--enable-lttng"; fi && \
    ./configure \
       --prefix=/usr \
       --sysconfdir=/etc \
       --localstatedir=/var \
       --sbindir=/usr/lib/frr \
       --enable-gcov \
       --enable-dev-build \
       --enable-mgmtd-test-be-client \
       --enable-rpki \
       --enable-sharpd \
       --enable-multipath=256 \
       --enable-user=frr \
       --enable-group=frr \
       --enable-config-rollbacks \
       --enable-grpc \
       --enable-protobuf \
       --enable-vty-group=frrvty \
       --enable-snmp \
       --enable-scripting \
       $LTTNG_OPT \
       --with-pkg-extra-version=-my-manual-build && \
    export PATH="/usr/local/lib/ccache:$PATH" && \
    make -j $(nproc) && \
    ccache -s && \
    sudo make install

RUN --mount=type=cache,id=frr-ccache,target=/home/frr/.ccache,uid=1010,gid=92,sharing=locked \
    cd ~/frr && export PATH="/usr/local/lib/ccache:$PATH" && \
    ccache -z && make check && ccache -s && \
    ccache --evict-older-than \
        "$(( $(date +%s) - $(stat -c %Y "$CCACHE_DIR/frr-build-start") + 1 ))s"

COPY docker/ubuntu-ci/docker-start /usr/sbin/docker-start
CMD ["/usr/sbin/docker-start"]
