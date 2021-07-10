# This library is free software: you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public
# License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.

# This library is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.
#
# You should have received a copy of the GNU Lesser General Public
# License along with this library.  If not, see <http://www.gnu.org/licenses/> or <http://www.gnu.org/licenses/lgpl.txt>

import urllib.request
import urllib.error
import http.client
import socket
from urllib.response import addinfourl
try:
    from . import ntlm
except (ValueError, ImportError):
    import ntlm.ntlm
import re
from typing import Optional


class AbstractNtlmAuthHandler:

    def __init__(self, password_mgr=None):
        if password_mgr is None:
            password_mgr = urllib.request.HTTPPasswordMgr()
        self.passwd = password_mgr
        self.add_password = self.passwd.add_password

    def http_error_authentication_required(self, auth_header_field: str, req: urllib.request, fp, headers) -> \
            Optional[addinfourl]:
        auth_header_value_list = headers.get_all(auth_header_field)
        if auth_header_value_list:
            if any([hv.lower() == 'ntlm' for hv in auth_header_value_list]):
                fp.close()
                return self.retry_using_http_ntlm_auth(req, auth_header_field, None, headers)

    def retry_using_http_ntlm_auth(self, req: urllib.request, auth_header_field, realm, headers):  # pylint:disable=too-many-statements
        logon_name, pw = self.passwd.find_user_password(realm, req.get_full_url())
        if pw is not None:
            user_parts = logon_name.split('\\', 1)
            if len(user_parts) == 1:
                user_name = user_parts[0]
                domain_name = ''
                type1_flags = ntlm.NTLM_TYPE1_FLAGS & ~ntlm.NTLM_NegotiateOemDomainSupplied
            else:
                domain_name = user_parts[0].upper()
                user_name = user_parts[1]
                type1_flags = ntlm.NTLM_TYPE1_FLAGS
            # ntlm secures a socket, so we must use the same socket for the complete handshake
            headers = dict(req.headers)
            headers.update(req.unredirected_hdrs)
            auth = 'NTLM {}'.format(ntlm.create_ntlm_negotiate_message(logon_name, type1_flags))
            if req.headers.get(self.auth_header, None) == auth:
                return None
            headers[self.auth_header] = auth

            host = req.host
            if not host:
                raise urllib.request.URLError('no host given')

            if req.get_full_url().startswith('https://'):
                conn = http.client.HTTPSConnection(host)  # will parse host:port
            else:
                conn = http.client.HTTPConnection(host)  # will parse host:port
            # we must keep the connection because NTLM authenticates the connection, not single requests
            headers["Connection"] = "Keep-Alive"
            headers = dict((name.title(), val) for name, val in list(headers.items()))
            conn.request(req.get_method(), req.selector, req.data, headers)
            resp = conn.getresponse()
            resp.begin()
            resp._safe_read(int(resp.getheader('content-length')))

            try:
                if resp.getheader('set-cookie'):
                    # this is important for some web applications that store authentication-related info in cookies (it
                    # took a long time to figure out)
                    headers['Cookie'] = resp.getheader('set-cookie')
            except TypeError:
                pass
            # remove the reference to the socket, so that it can not be closed by the response object (we want to keep
            # the socket open)
            resp.fp = None
            auth_header_value = resp.getheader(auth_header_field, None)

            # some Exchange servers send two WWW-Authenticate headers, one with the NTLM challenge
            # and another with the 'Negotiate' keyword - make sure we operate on the right one
            match = re.match(r'(NTLM [A-Za-z0-9+\-/=]+)', auth_header_value)
            if match:
                auth_header_value, = match.groups()

            (ServerChallenge, NegotiateFlags) = ntlm.parse_ntlm_challenge_message(auth_header_value[5:])
            auth = 'NTLM {}'.format(ntlm.create_ntlm_authenticate_message(
                ServerChallenge, user_name, domain_name, pw, NegotiateFlags
            ))
            headers[self.auth_header] = auth
            headers["Connection"] = "Close"
            headers = dict((name.title(), val) for name, val in list(headers.items()))
            try:
                conn.request(req.get_method(), req.selector, req.data, headers)
                # none of the configured handlers are triggered, for example redirect-responses are not handled!
                resp = conn.getresponse()

                def notimplemented():
                    raise NotImplementedError

                resp.readline = notimplemented
                return addinfourl(resp, resp.msg, req.get_full_url(), resp.code)
            except socket.error as err:
                raise urllib.request.URLError(err)
        else:
            return None


class HTTPNtlmAuthHandler(AbstractNtlmAuthHandler, urllib.request.BaseHandler):

    auth_header = 'Authorization'

    def http_error_401(self, req: urllib.request, fp, code, msg, headers):  # pylint:too-many-arguments,unused-arguments
        return self.http_error_authentication_required('www-authenticate', req, fp, headers)


class ProxyNtlmAuthHandler(AbstractNtlmAuthHandler, urllib.request.BaseHandler):
    """
        CAUTION: this class has NOT been tested at all!!!
        use at your own risk
    """
    auth_header = 'Proxy-authorization'

    def http_error_407(self, req: urllib.request, fp, code, msg, headers):  # pylint:disable=unused-argument
        return self.http_error_authentication_required('proxy-authenticate', req, fp, headers)


if __name__ == "__main__":
    URL = "http://ntlmprotectedserver/securedfile.html"
    USER = "DOMAIN\\User"
    PASSWORD = "Password"
    passman = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    passman.add_password(None, URL, USER, PASSWORD)
    auth_basic = urllib.request.HTTPBasicAuthHandler(passman)
    auth_digest = urllib.request.HTTPDigestAuthHandler(passman)
    auth_NTLM = HTTPNtlmAuthHandler(passman)

    # disable proxies (just for testing)
    proxy_handler = urllib.request.ProxyHandler({})

    opener = urllib.request.build_opener(proxy_handler, auth_NTLM)

    urllib.request.install_opener(opener)

    response = urllib.request.urlopen(URL)
    print((response.read()))
