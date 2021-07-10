"""Constants used in the test suite"""

# The headers seen during an initial NTML rejection.
INITIAL_REJECTION = b'''HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: NTLM
Connection: close
Date: Tue, 03 Feb 2009 11:47:33 GMT
Connection: close

'''

# The headers and data seen following a successful NTML connection.
EVENTUAL_SUCCESS = b'''HTTP/1.1 200 OK
Server: Apache-Coyote/1.1
WWW-Authenticate: NTLM TlRMTVNTUAACAAAABAAEADgAAAAFgomi3k7KRx+HGYQAAAAAAAAAALQAtAA8AAAABgGwHQAAAA9OAEEAAgAEAE4AQQABABYATgBBAFMAQQBOAEUAWABIAEMAMAA0AAQAHgBuAGEALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQADADYAbgBhAHMAYQBuAGUAeABoAGMAMAA0AC4AbgBhAC4AcQB1AGEAbABjAG8AbQBtAC4AYwBvAG0ABQAiAGMAbwByAHAALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQAHAAgADXHouNLjzAEAAAAA
Date: Tue, 03 Feb 2009 11:47:33 GMT
Connection: close

Hello, world!'''

# A collection of transactions representing various defects in NTLM
# processing. Each is indexed according the the issues number recorded
# for the defect at code.google.com, and consists of a series of server
# responses that should be seen as a connection is attempted.
ISSUES = {
    27: [
        INITIAL_REJECTION,
        b'''HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: NTLM TlRMTVNTUAACAAAABAAEADgAAAAFgomi3k7KRx+HGYQAAAAAAAAAALQAtAA8AAAABgGwHQAAAA9OAEEAAgAEAE4AQQABABYATgBBAFMAQQBOAEUAWABIAEMAMAA0AAQAHgBuAGEALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQADADYAbgBhAHMAYQBuAGUAeABoAGMAMAA0AC4AbgBhAC4AcQB1AGEAbABjAG8AbQBtAC4AYwBvAG0ABQAiAGMAbwByAHAALgBxAHUAYQBsAGMAbwBtAG0ALgBjAG8AbQAHAAgADXHouNLjzAEAAAAA
WWW-Authenticate: Negotiate
Content-Length: 0
Date: Tue, 03 Feb 2009 11:47:33 GMT
Connection: close

''',
        EVENTUAL_SUCCESS,
    ],
    28: [
        INITIAL_REJECTION,
        b'''HTTP/1.1 401 Unauthorized
Server: Apache-Coyote/1.1
WWW-Authenticate: NTLM TlRMTVNTUAACAAAAAAAAAAAAAAABAgAAO/AU3OJc3g0=
Content-Length: 0
Date: Tue, 03 Feb 2009 11:47:33 GMT
Connection: close

''',
        EVENTUAL_SUCCESS,
    ],
}
