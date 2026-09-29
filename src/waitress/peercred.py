##############################################################################
#
# Copyright (c) 2001, 2002 Zope Foundation and Contributors.
# All Rights Reserved.
#
# This software is subject to the provisions of the Zope Public License,
# Version 2.1 (ZPL).  A copy of the ZPL should accompany this distribution.
# THIS SOFTWARE IS PROVIDED "AS IS" AND ANY AND ALL EXPRESS OR IMPLIED
# WARRANTIES ARE DISCLAIMED, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF TITLE, MERCHANTABILITY, AGAINST INFRINGEMENT, AND FITNESS
# FOR A PARTICULAR PURPOSE.
#
##############################################################################
"""Query the kernel for the credentials of the peer of a Unix domain socket.

The values returned here are reported by the operating system kernel, they
cannot be forged by the process at the other end of the connection.
"""

import socket
import struct
import sys
from collections import namedtuple

#: The kernel-verified credentials of the process at the other end of a
#: Unix domain socket. ``pid`` is ``None`` on platforms whose kernel does
#: not report it (FreeBSD, macOS).
PeerCredentials = namedtuple("PeerCredentials", ("pid", "uid", "gid"))


class PeerCredentialsUnsupported(Exception):
    """The platform has no mechanism to query Unix socket peer credentials."""


# Socket option constants, with fallbacks for platforms where the socket
# module does not expose them. The values are stable ABI constants of the
# respective operating systems.
_SO_PEERCRED = getattr(socket, "SO_PEERCRED", 17)  # Linux: 17, OpenBSD: 0x1022
_OPENBSD_SO_PEERCRED = 0x1022
_SOL_LOCAL = getattr(socket, "SOL_LOCAL", 0)
_LOCAL_PEERCRED = getattr(socket, "LOCAL_PEERCRED", 0x001)  # FreeBSD, macOS
_LOCAL_PEEREID = getattr(socket, "LOCAL_PEEREID", 0x003)  # NetBSD

_XUCRED_VERSION = 0


def _unpack_linux_ucred(data):
    # struct ucred { pid_t pid; uid_t uid; gid_t gid; }
    pid, uid, gid = struct.unpack("3i", data)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def _unpack_bsd_xucred(data):
    # struct xucred { u_int cr_version; uid_t cr_uid; short cr_ngroups;
    #                 gid_t cr_groups[NGROUPS]; }
    # The native layout inserts padding after cr_ngroups, so use native
    # alignment; only the version, the effective uid and the first group
    # (the effective gid) are of interest. xucred carries no pid.
    fmt = "@IIhI"
    cr_version, uid, _ngroups, gid = struct.unpack(fmt, data[: struct.calcsize(fmt)])
    if cr_version != _XUCRED_VERSION:
        raise OSError(f"kernel returned unknown xucred version {cr_version}")
    return PeerCredentials(pid=None, uid=uid, gid=gid)


def _unpack_openbsd_sockpeercred(data):
    # struct sockpeercred { uid_t uid; gid_t gid; pid_t pid; }
    uid, gid, pid = struct.unpack("3i", data)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def _unpack_netbsd_unpcbid(data):
    # struct unpcbid { pid_t unp_pid; uid_t unp_euid; gid_t unp_egid; }
    pid, uid, gid = struct.unpack("3i", data)
    return PeerCredentials(pid=pid, uid=uid, gid=gid)


def _query_linux(sock):
    data = sock.getsockopt(socket.SOL_SOCKET, _SO_PEERCRED, struct.calcsize("3i"))
    return _unpack_linux_ucred(data)


def _query_bsd_xucred(sock):
    data = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEERCRED, struct.calcsize("@IIhI"))
    return _unpack_bsd_xucred(data)


def _query_openbsd(sock):
    data = sock.getsockopt(
        socket.SOL_SOCKET, _OPENBSD_SO_PEERCRED, struct.calcsize("3i")
    )
    return _unpack_openbsd_sockpeercred(data)


def _query_netbsd(sock):
    data = sock.getsockopt(_SOL_LOCAL, _LOCAL_PEEREID, struct.calcsize("3i"))
    return _unpack_netbsd_unpcbid(data)


def _platform_query(platform):
    if platform.startswith("linux"):
        return _query_linux
    if platform.startswith(("darwin", "freebsd", "dragonfly")):
        return _query_bsd_xucred
    if platform.startswith("openbsd"):
        return _query_openbsd
    if platform.startswith("netbsd"):
        return _query_netbsd
    return None


def get_peer_credentials(sock):
    """Return the kernel-verified credentials of the peer of ``sock``.

    ``sock`` must be a connected Unix domain socket. Returns a
    ``PeerCredentials`` named tuple ``(pid, uid, gid)``; ``pid`` is ``None``
    on platforms whose kernel does not report it.

    Raises :exc:`PeerCredentialsUnsupported` if the platform provides no
    mechanism to query the credentials. Raises :exc:`OSError` if the
    platform supports the query but the query itself failed.
    """
    query = _platform_query(sys.platform)
    if query is None:
        raise PeerCredentialsUnsupported(
            "querying Unix socket peer credentials is not supported "
            f"on platform {sys.platform!r}"
        )
    try:
        return query(sock)
    except struct.error as exc:
        # The kernel returned something we could not parse; that is a
        # failed query, not an unsupported platform.
        raise OSError(f"could not parse peer credentials: {exc}")
