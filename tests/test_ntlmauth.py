"""Demonstrate various defects (or their repair!) in the ntml module."""
import urllib.request


def test_negotiate(url):
    """Tests with this issue: https://code.google.com/archive/p/python-ntlm/issues/30"""
    with urllib.request.urlopen(url.format('27')) as data:
        assert data.read() == b'Hello, world!'


def test_non_negotiate(url):
    """Tests with the request without negotiate and with
    WWW-Authenticate: NTLM TlRMTVNTUAACAAAAAAAAAAAAAAABAgAAO/AU3OJc3g0=. See constants.ISSUES for the data"""
    with urllib.request.urlopen(url.format('28')) as data:
        assert data.read() == b'Hello, world!'
