import os
import socket
import struct
import sys
import unittest
from unittest import mock


class FakeSock:
    family = getattr(socket, "AF_UNIX", None)

    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.queries = []

    def getsockopt(self, *args):
        self.queries.append(args)
        if self.error is not None:
            raise self.error
        return self.result


class TestGetPeerCredentials(unittest.TestCase):
    def _callFUT(self, sock):
        from waitress.peercred import get_peer_credentials

        return get_peer_credentials(sock)

    @unittest.skipUnless(hasattr(socket, "AF_UNIX"), "need Unix domain sockets")
    @unittest.skipUnless(
        sys.platform.startswith("linux"), "real credentials are Linux-specific"
    )
    def test_linux_local_socket_returns_real_credentials(self):
        # The kernel reports the credentials of the process at the other end
        # of the socketpair, which is this very process.
        server, client = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            try:
                creds = self._callFUT(server)
            except PermissionError as exc:  # pragma: no cover
                # some sandboxed environments (seccomp) deny SO_PEERCRED
                raise unittest.SkipTest(
                    f"SO_PEERCRED is not permitted in this environment: {exc}"
                )
        finally:
            server.close()
            client.close()
        self.assertEqual(creds.pid, os.getpid())
        self.assertEqual(creds.uid, os.getuid())
        self.assertEqual(creds.gid, os.getgid())

    def test_linux_ucred_format(self):
        import waitress.peercred
        from waitress.peercred import PeerCredentials

        sock = FakeSock(result=struct.pack("3i", 123, 1000, 1001))
        with mock.patch.object(sys, "platform", "linux"):
            creds = self._callFUT(sock)
        self.assertEqual(creds, PeerCredentials(pid=123, uid=1000, gid=1001))
        level, optname, buflen = sock.queries[0]
        self.assertEqual(level, socket.SOL_SOCKET)
        self.assertEqual(optname, waitress.peercred._SO_PEERCRED)
        self.assertEqual(buflen, struct.calcsize("3i"))

    def test_darwin_xucred_format(self):
        from waitress.peercred import PeerCredentials

        # struct xucred: version, uid, ngroups, groups[0] (native alignment)
        sock = FakeSock(result=struct.pack("@IIhI", 0, 501, 1, 20))
        with mock.patch.object(sys, "platform", "darwin"):
            creds = self._callFUT(sock)
        # xucred carries no pid
        self.assertEqual(creds, PeerCredentials(pid=None, uid=501, gid=20))
        level, optname, buflen = sock.queries[0]
        self.assertEqual(level, 0)  # SOL_LOCAL
        self.assertEqual(optname, 0x001)  # LOCAL_PEERCRED

    def test_freebsd_xucred_format(self):
        from waitress.peercred import PeerCredentials

        sock = FakeSock(result=struct.pack("@IIhI", 0, 65534, 2, 65534))
        with mock.patch.object(sys, "platform", "freebsd14"):
            creds = self._callFUT(sock)
        self.assertEqual(creds, PeerCredentials(pid=None, uid=65534, gid=65534))

    def test_bsd_xucred_unknown_version_is_query_failure(self):
        sock = FakeSock(result=struct.pack("@IIhI", 99, 501, 1, 20))
        with mock.patch.object(sys, "platform", "darwin"):
            self.assertRaises(OSError, self._callFUT, sock)

    def test_openbsd_sockpeercred_format(self):
        from waitress.peercred import PeerCredentials

        # struct sockpeercred { uid_t uid; gid_t gid; pid_t pid; }
        sock = FakeSock(result=struct.pack("3i", 1000, 1001, 123))
        with mock.patch.object(sys, "platform", "openbsd7"):
            creds = self._callFUT(sock)
        self.assertEqual(creds, PeerCredentials(pid=123, uid=1000, gid=1001))
        level, optname, buflen = sock.queries[0]
        self.assertEqual(level, socket.SOL_SOCKET)
        self.assertEqual(optname, 0x1022)  # SO_PEERCRED on OpenBSD

    def test_netbsd_unpcbid_format(self):
        from waitress.peercred import PeerCredentials

        # struct unpcbid { pid_t unp_pid; uid_t unp_euid; gid_t unp_egid; }
        sock = FakeSock(result=struct.pack("3i", 123, 1000, 1001))
        with mock.patch.object(sys, "platform", "netbsd10"):
            creds = self._callFUT(sock)
        self.assertEqual(creds, PeerCredentials(pid=123, uid=1000, gid=1001))
        level, optname, buflen = sock.queries[0]
        self.assertEqual(level, 0)  # SOL_LOCAL
        self.assertEqual(optname, 0x003)  # LOCAL_PEEREID

    def test_unsupported_platform(self):
        from waitress.peercred import PeerCredentialsUnsupported

        sock = FakeSock(result=b"")
        with mock.patch.object(sys, "platform", "win32"):
            self.assertRaises(PeerCredentialsUnsupported, self._callFUT, sock)
        # an unsupported platform must not even attempt the query
        self.assertEqual(sock.queries, [])

    def test_query_failure_raises_oserror(self):
        sock = FakeSock(error=OSError("boom"))
        with mock.patch.object(sys, "platform", "linux"):
            self.assertRaises(OSError, self._callFUT, sock)

    def test_unparseable_kernel_reply_is_query_failure(self):
        sock = FakeSock(result=b"\x00")  # too short for any known struct
        with mock.patch.object(sys, "platform", "linux"):
            self.assertRaises(OSError, self._callFUT, sock)
