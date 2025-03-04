# python-ntlm
Python library that provides NTLM support, including an authentication handler for urllib2.

This library allows you to retrieve content from (usually corporate) servers protected with windows authentication (NTLM) using the python urllib2.

# Usage

## Simple example
```python
import urllib2
from ntlm import HTTPNtlmAuthHandler

user = 'DOMAIN\User'
password = "Password"
url = "http://ntlmprotectedserver/securedfile.html"

passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
passman.add_password(None, url, user, password)
# create the NTLM authentication handler
auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)

# create and install the opener
opener = urllib2.build_opener(auth_NTLM)
urllib2.install_opener(opener)

# retrieve the result
response = urllib2.urlopen(url)
print(response.read())
```

## Extended Example
```python
import urllib2
from urlparse import urlparse, urlunparse
from ntlm import HTTPNtlmAuthHandler

user = 'DOMAIN\User'
password = "Password"
url = "http://ntlmprotectedserver/securedfile.html"
# determine a base_uri for which the username and password can be used
parsed_url = urlparse(self.href)
base_uri = urlunparse((parsed_url[0],parsed_url[1],"","","",""))

passman = urllib2.HTTPPasswordMgrWithDefaultRealm()
passman.add_password(None, base_uri, user, password)
# create the NTLM authentication handler
auth_NTLM = HTTPNtlmAuthHandler.HTTPNtlmAuthHandler(passman)

# other authentication handlers
auth_basic = urllib2.HTTPBasicAuthHandler(passman)
auth_digest = urllib2.HTTPDigestAuthHandler(passman)

# disable proxies (if you want to stay within the corporate network)
proxy_handler = urllib2.ProxyHandler({})

# create and install the opener
opener = urllib2.build_opener(proxy_handler, auth_NTLM, auth_digest, auth_basic)
urllib2.install_opener(opener)

# retrieve the result    
response = urllib2.urlopen(url)
print(response.read())
```

## Limitations
  * A request using the `HTTPNtlmAuthHandler` has no HTTP status handling, for example: redirects are not handled by the opener, you must check and handle the response yourself.

# Resources

## Inspired by
  * [http://sourceforge.net/projects/ntlmaps/ NTLM Authorization Proxy Server]
(Dmitri Rozmanov kindly allowed his code to be redistributed under the LGPL)

The NTLM Authorization Proxy Server can be used to make applications that do not support NTLM proxies use them anyway: "Opens up IIS Proxy Servers using NTLM to non-Microsoft browsers, etc"

In contrast the python-ntlm library is used to make it possible for python code to retrieve content from an NTLM protected server. 

## References
  * [MS-NLMP]: [http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NLMP%5D.pdf NT LAN Manager (NTLM) Authentication Protocol Specification]
  * [MS-NTHT]: [http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NTHT%5D.pdf NTLM Over HTTP Protocol Specification]
  * [http://www.blackhat.com/presentations/bh-asia-04/bh-jp-04-pdfs/bh-jp-04-seki.pdf Optimized Attack for NTLM2 Session Response]
