##############################################################################
#
# Copyright (c) 2002 Zope Foundation and Contributors.
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

import unittest
import unittest.mock


def _hide_socket_attr(name):
    """Context manager that makes ``hasattr(socket, name)`` false."""
    import contextlib
    import socket

    @contextlib.contextmanager
    def hide():
        sentinel = object()
        saved = getattr(socket, name, sentinel)
        if saved is not sentinel:
            delattr(socket, name)
        try:
            yield
        finally:
            if saved is not sentinel:
                setattr(socket, name, saved)

    return hide()


class Test_get_peer_credentials(unittest.TestCase):
    def _callFUT(self, sock):
        from waitress.utilities import get_peer_credentials

        return get_peer_credentials(sock)

    def _makeSock(self, getsockopt):
        class Sock:
            pass

        sock = Sock()
        sock.getsockopt = getsockopt
        return sock

    def test_linux_so_peercred(self):
        import socket
        import struct

        from waitress.utilities import PeerCredentials

        calls = []

        def getsockopt(level, optname, buflen):
            calls.append((level, optname, buflen))
            return struct.pack("3i", 4321, 1000, 1001)

        with unittest.mock.patch.object(socket, "SO_PEERCRED", 17, create=True):
            result = self._callFUT(self._makeSock(getsockopt))

        self.assertEqual(result, PeerCredentials(pid=4321, uid=1000, gid=1001))
        self.assertEqual(calls, [(socket.SOL_SOCKET, 17, struct.calcsize("3i"))])

    def test_bsd_local_peercred(self):
        import socket
        import struct

        from waitress.utilities import PeerCredentials

        # struct xucred: version, uid, ngroups, then the group list whose
        # first entry is the effective gid; there is no pid. cr_groups is
        # aligned to a 4 byte boundary, hence the 2 padding bytes.
        creds = struct.pack("@IIh2xI", 1, 1002, 1, 1003)
        creds += b"\x00" * (256 - len(creds))

        calls = []

        def getsockopt(level, optname, buflen):
            calls.append((level, optname, buflen))
            return creds

        with _hide_socket_attr("SO_PEERCRED"), unittest.mock.patch.multiple(
            socket, LOCAL_PEERCRED=1, SOL_LOCAL=0, create=True
        ):
            result = self._callFUT(self._makeSock(getsockopt))

        self.assertEqual(result, PeerCredentials(pid=None, uid=1002, gid=1003))
        self.assertEqual(calls, [(0, 1, 256)])

    def test_unsupported_platform_returns_none(self):
        def getsockopt(level, optname, buflen):  # pragma: no cover
            raise AssertionError("must not be called")

        with _hide_socket_attr("SO_PEERCRED"), _hide_socket_attr(
            "LOCAL_PEERCRED"
        ):
            result = self._callFUT(self._makeSock(getsockopt))

        self.assertIsNone(result)

    def test_query_failure_raises_oserror(self):
        import socket

        def getsockopt(level, optname, buflen):
            raise OSError("socket is not connected")

        with unittest.mock.patch.object(socket, "SO_PEERCRED", 17, create=True):
            self.assertRaises(OSError, self._callFUT, self._makeSock(getsockopt))

    def test_short_creds_raises_oserror(self):
        import socket

        def getsockopt(level, optname, buflen):
            return b"\x00\x00"

        with unittest.mock.patch.object(socket, "SO_PEERCRED", 17, create=True):
            self.assertRaises(OSError, self._callFUT, self._makeSock(getsockopt))

    def test_short_xucred_raises_oserror(self):
        import socket

        def getsockopt(level, optname, buflen):
            return b"\x00\x00"

        with _hide_socket_attr("SO_PEERCRED"), unittest.mock.patch.multiple(
            socket, LOCAL_PEERCRED=1, SOL_LOCAL=0, create=True
        ):
            self.assertRaises(OSError, self._callFUT, self._makeSock(getsockopt))


class Test_parse_http_date(unittest.TestCase):
    def _callFUT(self, v):
        from waitress.utilities import parse_http_date

        return parse_http_date(v)

    def test_rfc850(self):
        val = "Tuesday, 08-Feb-94 14:15:29 GMT"
        result = self._callFUT(val)
        self.assertEqual(result, 760716929)

    def test_rfc822(self):
        val = "Sun, 08 Feb 1994 14:15:29 GMT"
        result = self._callFUT(val)
        self.assertEqual(result, 760716929)

    def test_neither(self):
        val = ""
        result = self._callFUT(val)
        self.assertEqual(result, 0)


class Test_build_http_date(unittest.TestCase):
    def test_rountdrip(self):
        from time import time

        from waitress.utilities import build_http_date, parse_http_date

        t = int(time())
        self.assertEqual(t, parse_http_date(build_http_date(t)))


class Test_unpack_rfc850(unittest.TestCase):
    def _callFUT(self, val):
        from waitress.utilities import rfc850_reg, unpack_rfc850

        return unpack_rfc850(rfc850_reg.match(val.lower()))

    def test_it(self):
        val = "Tuesday, 08-Feb-94 14:15:29 GMT"
        result = self._callFUT(val)
        self.assertTupleEqual(result, (1994, 2, 8, 14, 15, 29, 0, 0, 0))


class Test_unpack_rfc_822(unittest.TestCase):
    def _callFUT(self, val):
        from waitress.utilities import rfc822_reg, unpack_rfc822

        return unpack_rfc822(rfc822_reg.match(val.lower()))

    def test_it(self):
        val = "Sun, 08 Feb 1994 14:15:29 GMT"
        result = self._callFUT(val)
        self.assertTupleEqual(result, (1994, 2, 8, 14, 15, 29, 0, 0, 0))


class Test_find_double_newline(unittest.TestCase):
    def _callFUT(self, val):
        from waitress.utilities import find_double_newline

        return find_double_newline(val)

    def test_empty(self):
        self.assertEqual(self._callFUT(b""), -1)

    def test_one_linefeed(self):
        self.assertEqual(self._callFUT(b"\n"), -1)

    def test_double_linefeed(self):
        self.assertEqual(self._callFUT(b"\n\n"), -1)

    def test_one_crlf(self):
        self.assertEqual(self._callFUT(b"\r\n"), -1)

    def test_double_crfl(self):
        self.assertEqual(self._callFUT(b"\r\n\r\n"), 4)

    def test_mixed(self):
        self.assertEqual(self._callFUT(b"\n\n00\r\n\r\n"), 8)


class TestBadRequest(unittest.TestCase):
    def _makeOne(self):
        from waitress.utilities import BadRequest

        return BadRequest(1)

    def test_it(self):
        inst = self._makeOne()
        self.assertEqual(inst.body, 1)


class Test_undquote(unittest.TestCase):
    def _callFUT(self, value):
        from waitress.utilities import undquote

        return undquote(value)

    def test_empty(self):
        self.assertEqual(self._callFUT(""), "")

    def test_quoted(self):
        self.assertEqual(self._callFUT('"test"'), "test")

    def test_unquoted(self):
        self.assertEqual(self._callFUT("test"), "test")

    def test_quoted_backslash_quote(self):
        self.assertEqual(self._callFUT('"\\""'), '"')

    def test_quoted_htab(self):
        self.assertEqual(self._callFUT('"\t"'), "\t")

    def test_quoted_backslash_htab(self):
        self.assertEqual(self._callFUT('"\\\t"'), "\t")

    def test_quoted_backslash_invalid(self):
        self.assertRaises(ValueError, self._callFUT, '"\\"')

    def test_invalid_quoting(self):
        self.assertRaises(ValueError, self._callFUT, '"test')

    def test_invalid_quoting_single_quote(self):
        self.assertRaises(ValueError, self._callFUT, '"')
