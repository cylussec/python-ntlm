"""Pytest fixtures"""
import urllib.request
from io import BytesIO
import http.client

import pytest

from constants import ISSUES
from ntlm_handler import httpntlmauthhandler


class FakeSocket(BytesIO):
    """Extends BytesIO just enough to look like a socket."""

    def makefile(self, *args, **kwds):  # pylint:disable=unused-argument
        """The instance already looks like a file."""
        return self

    def sendall(self, *args, **kwds):
        """Ignore any data that may be sent."""

    def close(self):
        """Ignore any calls to close."""


class FakeHTTPConnection(http.client.HTTPConnection):
    """Looks like a normal HTTPConnection, but returns a FakeSocket.
    The connection's port number is used to choose a set of transactions
    to replay to the user.  A class static variable is used to track
    how many transactions have been replayed."""
    attempt = {}

    def connect(self):
        """Returns a FakeSocket containing the data for a single
        transaction."""
        nbr = self.attempt.setdefault(self.port, 0)
        self.attempt[self.port] = nbr + 1
        print('connecting to %s:%s (attempt %s)' % (self.host, self.port, nbr))
        self.sock = FakeSocket(ISSUES[self.port][nbr])


class FakeHTTPHandler(urllib.request.HTTPHandler):
    """Acts like a normal HTTPHander, except that it uses FakeHTTPConnection instead of HTTPConnection"""
    connection = FakeHTTPConnection

    def http_open(self, req):
        print('opening', self.connection)
        return self.do_open(self.connection, req)


@pytest.fixture(scope='session', name='url')
def fixture_server():
    """A fake server that we can connect to"""
    issue_nbrs = list(ISSUES.keys())

    user = 'DOMAIN\\User'
    password = "Password"
    url = "http://www.example.org:{}/"

    # Set passwords for each of the "servers" to which we will be connecting.
    # Each distinct port on a server requires it's own set of credentials.
    passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    for k in issue_nbrs:
        passman.add_password(None, url.format(k), user, password)

    # Create the NTLM authentication handler.
    auth_ntlm = httpntlmauthhandler.HTTPNtlmAuthHandler(passman)

    # Create and install openers for both the NTLM Auth handler and
    # our fake HTTP handler.
    opener = urllib.request.build_opener(auth_ntlm, FakeHTTPHandler)
    urllib.request.install_opener(opener)

    # The following is a massive kludge; let me explain why it is needed.
    httpntlmauthhandler.http.client.HTTPConnection = FakeHTTPConnection
    # At the heart of the urllib2 module is the opener director. Whenever a
    # URL is opened, the director is responsible for locating the proper
    # handler for the protocol specified in the URL. Frequently, an existing
    # protocol handler will be subclassed and then added to the collection
    # maintained by the director. When urlopen is called, the specified
    # request is immediately handed off to the director's "open" method
    # which finds the correct handler and invokes the protocol-specific
    # XXX_open method. At least in the case of the HTTP protocols, if an
    # error occurs then the director is called again to find and invoke a
    # handler for the error; these handlers generally open a new connection
    # after adding headers to avoid the error going forward. Finally, it is
    # important to note that at the present time, the HTTP handlers in
    # urllib2 are built using a class that isn't prepared to deal with a
    # persistent connection, so they always add a "Connection: close" header
    # to the request.
    #
    # Unfortunately, NTLM only certifies the current connection, meaning
    # that  a "Connection: keep-alive" header must be used to keep it open
    # throughout the authentication process. Furthermore, because the opener
    # director only provides a do_open method, there is no way to discover
    # the type of connection without also opening it. This means that the
    # HTTPNtlmAuthHandler cannot use the normal HTTPHandler and must
    # therefore must hardcode the HTTPConnection class. If a custom class is
    # required for whatever reason, the only way to cause it to be used is
    # to monkey-patch the code, as is done in the line above.
    return url
