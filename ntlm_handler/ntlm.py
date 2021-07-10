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

import base64
import binascii
import hashlib
import hmac
import random
import re
import struct
from socket import gethostname
from typing import AnyStr, Tuple

from Crypto.Cipher import DES

NTLM_NEGOTIATEUNICODE = 0x00000001
NTLM_NEGOTIATEOEM = 0x00000002
NTLM_REQUESTTARGET = 0x00000004
NTLM_UNKNOWN9 = 0x00000008
NTLM_NEGOTIATESIGN = 0x00000010
NTLM_NEGOTIATESEAL = 0x00000020
NTLM_NEGOTIATEDATAGRAM = 0x00000040
NTLM_NEGOTIATELANMANAGERKEY = 0x00000080
NTLM_UNKNOWN8 = 0x00000100
NTLM_NEGOTIATENTLM = 0x00000200
NTLM_NEGOTIATENTONLY = 0x00000400
NTLM_ANONYMOUS = 0x00000800
NTLM_NEGOTIATEOEMDOMAINSUPPLIED = 0x00001000
NTLM_NEGOTIATEOEMWORKSTATIONSUPPLIED = 0x00002000
NTLM_UNKNOWN6 = 0x00004000
NTLM_NEGOTIATEALWAYSSIGN = 0x00008000
NTLM_TARGETTYPEDOMAIN = 0x00010000
NTLM_TARGETTYPESERVER = 0x00020000
NTLM_TARGETTYPESHARE = 0x00040000
NTLM_NEGOTIATEEXTENDEDSECURITY = 0x00080000
NTLM_NEGOTIATEIDENTIFY = 0x00100000
NTLM_UNKNOWN5 = 0x00200000
NTLM_REQUESTNONNTSESSIONKEY = 0x00400000
NTLM_NEGOTIATETARGETINFO = 0x00800000
NTLM_UNKNOWN4 = 0x01000000
NTLM_NEGOTIATEVERSION = 0x02000000
NTLM_UNKNOWN3 = 0x04000000
NTLM_UNKNOWN2 = 0x08000000
NTLM_UNKNOWN1 = 0x10000000
NTLM_NEGOTIATE128 = 0x20000000
NTLM_NEGOTIATEKEYEXCHANGE = 0x40000000
NTLM_NEGOTIATE56 = 0x80000000

# we send these flags with our type 1 message
NTLM_TYPE1_FLAGS = (NTLM_NEGOTIATEUNICODE |
                    NTLM_NEGOTIATEOEM |
                    NTLM_REQUESTTARGET |
                    NTLM_NEGOTIATENTLM |
                    NTLM_NEGOTIATEOEMDOMAINSUPPLIED |
                    NTLM_NEGOTIATEOEMWORKSTATIONSUPPLIED |
                    NTLM_NEGOTIATEALWAYSSIGN |
                    NTLM_NEGOTIATEEXTENDEDSECURITY |
                    NTLM_NEGOTIATEVERSION |
                    NTLM_NEGOTIATE128 |
                    NTLM_NEGOTIATE56)
NTLM_TYPE2_FLAGS = (NTLM_NEGOTIATEUNICODE |
                    NTLM_REQUESTTARGET |
                    NTLM_NEGOTIATENTLM |
                    NTLM_NEGOTIATEALWAYSSIGN |
                    NTLM_NEGOTIATEEXTENDEDSECURITY |
                    NTLM_NEGOTIATETARGETINFO |
                    NTLM_NEGOTIATEVERSION |
                    NTLM_NEGOTIATE128 |
                    NTLM_NEGOTIATE56)
# Indicates that this is the last AV_PAIR in the list. AvLen MUST be 0. This type of information MUST be present in the
# AV pair list.
NTLM_MSVAVEOL = 0

# The server's NetBIOS computer name. The name MUST be in Unicode, and is not null-terminated. This type of information
# MUST be present in the AV_pair list.
NTLM_MSVAVNBCOMPUTERNAME = 1

# The server's NetBIOS domain name. The name MUST be in Unicode, and is not null-terminated. This type of information
# MUST be present in the AV_pair list.
NTLM_MSVAVNBDOMAINNAME = 2

# The server's Active Directory DNS computer name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MSVAVDNSCOMPUTERNAME = 3

# The server's Active Directory DNS domain name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MSVAVDNSDOMAINNAME = 4

# The server's Active Directory (AD) DNS forest tree name. The name MUST be in Unicode, and is not null-terminated.
NTLM_MSVAVDNSTREENAME = 5

# A field containing a 32-bit value indicating server or client configuration. 0x00000001: indicates to the client that
# the account authentication is constrained. 0x00000002: indicates that the client is providing message integrity in the
# MIC field (section 2.2.1.3) in the AUTHENTICATE_MESSAGE.
NTLM_MSVAVFLAGS = 6

# A FILETIME structure ([MS-DTYP] section 2.3.1) in little-endian byte order that contains the server local time.<12>
NTLM_MSVAVTIMESTAMP = 7

# A Restriction_Encoding structure (section 2.2.2.2). The Value field contains a structure representing the integrity
# level of the security principal, as well as a MachineID created at computer startup to identify the calling machine.
# <13>
NTLM_MSAVRESTRICTIONS = 8

NEGOTATE_BODY_LENGTH = 40
AUTHENTICATE_BODY_LENGTH = 72

"""
utility functions for Microsoft NTLM authentication

References:
[MS-NLMP]: NT LAN Manager (NTLM) Authentication Protocol Specification
http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NLMP%5D.pdf

[MS-NTHT]: NTLM Over HTTP Protocol Specification
http://download.microsoft.com/download/a/e/6/ae6e4142-aa58-45c6-8dcf-a657e5900cd3/%5BMS-NTHT%5D.pdf

Cntlm Authentication Proxy
http://cntlm.awk.cz/

NTLM Authorization Proxy Server
http://sourceforge.net/projects/ntlmaps/

Optimized Attack for NTLM2 Session Response
http://www.blackhat.com/presentations/bh-asia-04/bh-jp-04-pdfs/bh-jp-04-seki.pdf
"""


def dump_negotiate_flags(negotiate_flags):  # pylint:disable=too-many-branches,too-many-statements
    """Logging function for our flags"""
    if negotiate_flags & NTLM_NEGOTIATEUNICODE:
        print("NTLM_NEGOTIATEUNICODE set")
    if negotiate_flags & NTLM_NEGOTIATEOEM:
        print("NTLM_NEGOTIATEOEM set")
    if negotiate_flags & NTLM_REQUESTTARGET:
        print("NTLM_REQUESTTARGET set")
    if negotiate_flags & NTLM_UNKNOWN9:
        print("NTLM_UNKNOWN9 set")
    if negotiate_flags & NTLM_NEGOTIATESIGN:
        print("NTLM_NEGOTIATESIGN set")
    if negotiate_flags & NTLM_NEGOTIATESEAL:
        print("NTLM_NEGOTIATESEAL set")
    if negotiate_flags & NTLM_NEGOTIATEDATAGRAM:
        print("NTLM_NEGOTIATEDATAGRAM set")
    if negotiate_flags & NTLM_NEGOTIATELANMANAGERKEY:
        print("NTLM_NEGOTIATELANMANAGERKEY set")
    if negotiate_flags & NTLM_UNKNOWN8:
        print("NTLM_UNKNOWN8 set")
    if negotiate_flags & NTLM_NEGOTIATENTLM:
        print("NTLM_NEGOTIATENTLM set")
    if negotiate_flags & NTLM_NEGOTIATENTONLY:
        print("NTLM_NEGOTIATENTONLY set")
    if negotiate_flags & NTLM_ANONYMOUS:
        print("NTLM_ANONYMOUS set")
    if negotiate_flags & NTLM_NEGOTIATEOEMDOMAINSUPPLIED:
        print("NTLM_NEGOTIATEOEMDOMAINSUPPLIED set")
    if negotiate_flags & NTLM_NEGOTIATEOEMWORKSTATIONSUPPLIED:
        print("NTLM_NEGOTIATEOEMWORKSTATIONSUPPLIED set")
    if negotiate_flags & NTLM_UNKNOWN6:
        print("NTLM_UNKNOWN6 set")
    if negotiate_flags & NTLM_NEGOTIATEALWAYSSIGN:
        print("NTLM_NEGOTIATEALWAYSSIGN set")
    if negotiate_flags & NTLM_TARGETTYPEDOMAIN:
        print("NTLM_TARGETTYPEDOMAIN set")
    if negotiate_flags & NTLM_TARGETTYPESERVER:
        print("NTLM_TARGETTYPESERVER set")
    if negotiate_flags & NTLM_TARGETTYPESHARE:
        print("NTLM_TARGETTYPESHARE set")
    if negotiate_flags & NTLM_NEGOTIATEEXTENDEDSECURITY:
        print("NTLM_NEGOTIATEEXTENDEDSECURITY set")
    if negotiate_flags & NTLM_NEGOTIATEIDENTIFY:
        print("NTLM_NEGOTIATEIDENTIFY set")
    if negotiate_flags & NTLM_UNKNOWN5:
        print("NTLM_UNKNOWN5 set")
    if negotiate_flags & NTLM_REQUESTNONNTSESSIONKEY:
        print("NTLM_REQUESTNONNTSESSIONKEY set")
    if negotiate_flags & NTLM_NEGOTIATETARGETINFO:
        print("NTLM_NEGOTIATETARGETINFO set")
    if negotiate_flags & NTLM_UNKNOWN4:
        print("NTLM_UNKNOWN4 set")
    if negotiate_flags & NTLM_NEGOTIATEVERSION:
        print("NTLM_NEGOTIATEVERSION set")
    if negotiate_flags & NTLM_UNKNOWN3:
        print("NTLM_UNKNOWN3 set")
    if negotiate_flags & NTLM_UNKNOWN2:
        print("NTLM_UNKNOWN2 set")
    if negotiate_flags & NTLM_UNKNOWN1:
        print("NTLM_UNKNOWN1 set")
    if negotiate_flags & NTLM_NEGOTIATE128:
        print("NTLM_NEGOTIATE128 set")
    if negotiate_flags & NTLM_NEGOTIATEKEYEXCHANGE:
        print("NTLM_NEGOTIATEKEYEXCHANGE set")
    if negotiate_flags & NTLM_NEGOTIATE56:
        print("NTLM_NEGOTIATE56 set")


def create_ntlm_negotiate_message(user,  # pylint:disable=too-many-branches,too-many-statements
                                  type1_flags=NTLM_TYPE1_FLAGS):
    payload_start = NEGOTATE_BODY_LENGTH  # in bytes
    protocol = b'NTLMSSP\0'  # name

    type1 = struct.pack('<I', 1)  # type 1

    flags = struct.pack('<I', type1_flags)
    workstation = bytes(gethostname().upper(), 'ascii')
    user_parts = user.split('\\', 1)
    domain_name = bytes(user_parts[0].upper(), 'ascii')

    workstation_len = struct.pack('<H', len(workstation))
    workstation_max_len = struct.pack('<H', len(workstation))
    workstation_buffer_offset = struct.pack('<I', payload_start)
    payload_start += len(workstation)
    domain_name_len = struct.pack('<H', len(domain_name))
    domain_name_max_len = struct.pack('<H', len(domain_name))
    domain_name_buffer_offset = struct.pack('<I', payload_start)
    payload_start += len(domain_name)
    product_major_version = struct.pack('<B', 5)
    product_minor_version = struct.pack('<B', 1)
    product_build = struct.pack('<H', 2600)
    version_reserved1 = struct.pack('<B', 0)
    version_reserved2 = struct.pack('<B', 0)
    version_reserved3 = struct.pack('<B', 0)
    ntlm_revision_current = struct.pack('<B', 15)

    msg1 = protocol + type1 + flags + \
        domain_name_len + domain_name_max_len + domain_name_buffer_offset + \
        workstation_len + workstation_max_len + workstation_buffer_offset + \
        product_major_version + product_minor_version + product_build + \
        version_reserved1 + version_reserved2 + version_reserved3 + ntlm_revision_current

    assert NEGOTATE_BODY_LENGTH == len(msg1), "NEGOTATE_BODY_LENGTH: %d != msg1: %d" % (NEGOTATE_BODY_LENGTH, len(msg1))
    msg1 += workstation + domain_name
    msg1 = base64.b64encode(msg1)
    return msg1.decode()


def parse_ntlm_challenge_message(msg2):
    """
    Signature = msg2[0:8]
    msg_type = struct.unpack("<I", msg2[8:12])[0]
    assert (msg_type == 2)
    TargetNameLen = struct.unpack("<H", msg2[12:14])[0]
    TargetNameMaxLen = struct.unpack("<H", msg2[14:16])[0]
    TargetNameOffset = struct.unpack("<I", msg2[16:20])[0]
    TargetName = msg2[TargetNameOffset:TargetNameOffset + TargetNameMaxLen]
    NegotiateFlags = struct.unpack("<I", msg2[20:24])[0]
    ServerChallenge = msg2[24:32]
    if NegotiateFlags & NTLM_NEGOTIATETARGETINFO:
        Reserved = msg2[32:40]
        TargetInfoLen = struct.unpack("<H", msg2[40:42])[0]
        TargetInfoMaxLen = struct.unpack("<H", msg2[42:44])[0]
        TargetInfoOffset = struct.unpack("<I", msg2[44:48])[0]
    """
    msg2 = base64.decodebytes(bytes(msg2, 'ascii'))
    msg_type = struct.unpack("<I", msg2[8:12])[0]
    assert msg_type == 2
    negotiateflags = struct.unpack("<I", msg2[20:24])[0]
    serverchallenge = msg2[24:32]
    return serverchallenge, negotiateflags


def create_ntlm_authenticate_message(nonce, user, domain, password, negotiate_flags):
    is_unicode = negotiate_flags & NTLM_NEGOTIATEUNICODE
    is_negotiate_extended_security = negotiate_flags & NTLM_NEGOTIATEEXTENDEDSECURITY

    flags = struct.pack('<I', NTLM_TYPE2_FLAGS)

    payload_start = AUTHENTICATE_BODY_LENGTH  # in bytes

    workstation = bytes(gethostname().upper(), 'ascii')
    domain_name = bytes(domain.upper(), 'ascii')
    user_name = bytes(user, 'ascii')
    encrypted_random_session_key = b""
    if is_unicode:
        workstation = bytes(gethostname().upper(), 'utf-16-le')
        domain_name = bytes(domain.upper(), 'utf-16-le')
        user_name = bytes(user, 'utf-16-le')
        encrypted_random_session_key = bytes("", 'utf-16-le')
    lm_challenge_response = calc_resp(create_lm_hashed_password_v1(password), nonce)
    nt_challenge_response = calc_resp(create_NT_hashed_password_v1(password), nonce)

    if is_negotiate_extended_security:
        pwhash = create_NT_hashed_password_v1(password, user_name, domain_name)
        client_challenge = b""
        for i in range(8):
            client_challenge += bytes((random.getrandbits(8),))
        nt_challenge_response, lm_challenge_response = ntlm2sr_calc_resp(pwhash, nonce,
                                                                         client_challenge)  # ='\x39 e3 f4 cd 59 c5 d8 60')
    signature = b'NTLMSSP\0'
    message_type = struct.pack('<I', 3)  # type 3

    domain_name_len = struct.pack('<H', len(domain_name))
    domain_name_max_len = struct.pack('<H', len(domain_name))
    domain_name_offset = struct.pack('<I', payload_start)
    payload_start += len(domain_name)

    user_name_len = struct.pack('<H', len(user_name))
    user_name_max_len = struct.pack('<H', len(user_name))
    user_name_offset = struct.pack('<I', payload_start)
    payload_start += len(user_name)

    workstation_len = struct.pack('<H', len(workstation))
    workstation_max_len = struct.pack('<H', len(workstation))
    workstation_offset = struct.pack('<I', payload_start)
    payload_start += len(workstation)

    lm_challenge_response_len = struct.pack('<H', len(lm_challenge_response))
    lm_challenge_response_max_len = struct.pack('<H', len(lm_challenge_response))
    lm_challenge_response_offset = struct.pack('<I', payload_start)
    payload_start += len(lm_challenge_response)

    nt_challenge_response_len = struct.pack('<H', len(nt_challenge_response))
    nt_challenge_response_max_len = struct.pack('<H', len(nt_challenge_response))
    nt_challenge_response_offset = struct.pack('<I', payload_start)
    payload_start += len(nt_challenge_response)

    encrypted_random_session_key_len = struct.pack('<H', len(encrypted_random_session_key))
    encrypted_random_session_key_max_len = struct.pack('<H', len(encrypted_random_session_key))
    encrypted_random_session_key_offset = struct.pack('<I', payload_start)
    payload_start += len(encrypted_random_session_key)
    negotiate_flags = flags

    product_major_version = struct.pack('<B', 5)
    product_minor_version = struct.pack('<B', 1)
    product_build = struct.pack('<H', 2600)
    version_reserved1 = struct.pack('<B', 0)
    version_reserved2 = struct.pack('<B', 0)
    version_reserved3 = struct.pack('<B', 0)
    ntlm_revision_current = struct.pack('<B', 15)

    MIC = struct.pack('<IIII', 0, 0, 0, 0)
    msg3 = signature + message_type + \
           lm_challenge_response_len + lm_challenge_response_max_len + lm_challenge_response_offset + \
           nt_challenge_response_len + nt_challenge_response_max_len + nt_challenge_response_offset + \
           domain_name_len + domain_name_max_len + domain_name_offset + \
           user_name_len + user_name_max_len + user_name_offset + \
           workstation_len + workstation_max_len + workstation_offset + \
           encrypted_random_session_key_len + encrypted_random_session_key_max_len + encrypted_random_session_key_offset + \
           negotiate_flags + \
           product_major_version + product_minor_version + product_build + \
           version_reserved1 + version_reserved2 + version_reserved3 + ntlm_revision_current
    assert AUTHENTICATE_BODY_LENGTH == len(msg3), "AUTHENTICATE_BODY_LENGTH: %d != msg3: %d" % \
                                                  (AUTHENTICATE_BODY_LENGTH, len(msg3))
    payload = domain_name + user_name + workstation + lm_challenge_response + nt_challenge_response + \
              encrypted_random_session_key
    msg3 += payload
    msg3 = base64.b64encode(msg3)
    return msg3.decode()


def calc_resp(password_hash: bytes, server_challenge) -> bytes:
    """calc_resp generates the LM response given a 16-byte password hash and the
        challenge from the type-2 message.
        @param password_hash
            16-byte password hash
        @param server_challenge
            8-byte challenge from type-2 message
        returns
            24-byte buffer to contain the LM response upon return
    """
    # padding with zeros to make the hash 21 bytes long
    password_hash += b'\0' * (21 - len(password_hash))
    res = b''
    dobj = DES.new(password_hash[0:7] + b'\0', DES.MODE_ECB)
    res = res + dobj.encrypt(server_challenge[0:8])

    dobj = DES.new(password_hash[7:14] + b'\0', DES.MODE_ECB)
    res = res + dobj.encrypt(server_challenge[0:8])

    dobj = DES.new(password_hash[14:21] + b'\0', DES.MODE_ECB)
    res = res + dobj.encrypt(server_challenge[0:8])
    return res


def compute_response(response_key_nt: bytes, response_key_lm: bytes, server_challenge,
                     client_challenge: bytes = b'\xaa' * 8, time: bytes = b'\0' * 8) -> \
        Tuple[bytes, bytes]:
    lm_challenge_response: bytes = hmac.new(response_key_lm, server_challenge + client_challenge).digest() + client_challenge

    response_rversion = b'\x01'
    hi_response_rversion = b'\x01'
    temp = response_rversion + hi_response_rversion + b'\0' * 6 + time + client_challenge + b'\0' * 4 + \
        server_challenge + b'\0' * 4
    nt_proof_str: bytes = hmac.new(response_key_nt, server_challenge + temp).digest()
    nt_challenge_response = nt_proof_str + temp

    hmac.new(response_key_nt, nt_proof_str).digest()
    return nt_challenge_response, lm_challenge_response


def ntlm2sr_calc_resp(response_key_nt, server_challenge, client_challenge=b'\xaa' * 8):
    lm_challenge_response = client_challenge + b'\0' * 16
    sess = hashlib.md5(server_challenge + client_challenge).digest()
    nt_challenge_response = calc_resp(response_key_nt, sess[0:8])
    return nt_challenge_response, lm_challenge_response


def create_lm_hashed_password_v1(passwd: AnyStr) -> bytes:
    """create LanManager hashed password"""
    # if the passwd provided is already a hash, we just return the first half
    if re.match(r'^[\w]{32}:[\w]{32}$', passwd):
        return binascii.unhexlify(passwd.split(':')[0])

    # fix the password length to 14 bytes
    passwd = passwd.upper()
    passwd += '\0' * (14 - len(passwd))
    lm_pw = bytes(passwd[0:14], 'utf8')

    # do hash
    magic_str = b"KGS!@#$%"  # page 57 in [MS-NLMP]

    res = b""
    dobj = DES.new(lm_pw[0:7] + b'\0', DES.MODE_ECB)
    res = res + dobj.encrypt(magic_str)

    dobj = DES.new(lm_pw[7:14] + b'\0', DES.MODE_ECB)
    res = res + dobj.encrypt(magic_str)

    return res


def create_NT_hashed_password_v1(passwd, user=None, domain=None):
    "create NT hashed password"
    # if the passwd provided is already a hash, we just return the second half
    if re.match(r'^[\w]{32}:[\w]{32}$', passwd):
        return binascii.unhexlify(passwd.split(':')[1])

    digest = hashlib.new('md4', passwd.encode('utf-16le')).digest()
    return digest


def create_nt_hashed_password_v2(passwd, user, domain):
    """create NT hashed password"""
    digest = create_NT_hashed_password_v1(passwd)

    return hmac.new(digest, (user.upper() + domain).encode('utf-16le')).digest()
    return digest


def create_sessionbasekey(password):
    """Gets the NTLM base key"""
    return hashlib.new('md4', create_NT_hashed_password_v1(password)).digest()


if __name__ == "__main__":
    from binascii import unhexlify


    def byte_to_hex(byte_str):
        """
        Convert a byte string to it's hex string representation e.g. for output.
        """
        return ' '.join(["%02X" % x for x in byte_str])


    def hex_to_byte(hex_str):
        """
        Convert a string hex byte values into a byte string. The Hex Byte values may
        or may not be space separated.
        """
        hex_str = ''.join(hex_str.split(" "))

        return unhexlify(hex_str)


    SERVER_CHALLENGE = hex_to_byte("01 23 45 67 89 ab cd ef")
    CLIENT_CHALLENGE = b'\xaa' * 8
    TIME = b'\x00' * 8
    # WORKSTATION = "COMPUTER".encode('utf-16-le')
    SERVER_NAME = "Server".encode('utf-16-le')
    USER = "User"
    DOMAIN = "Domain"
    PASSWORD = "Password"
    RANDOM_SESSION_KEY = '\55' * 16
    assert hex_to_byte("e5 2c ac 67 41 9a 9a 22 4a 3b 10 8f 3f a6 cb 6d") == create_lm_hashed_password_v1(
        PASSWORD)  # [MS-NLMP] page 72
    assert hex_to_byte("a4 f4 9c 40 65 10 bd ca b6 82 4e e7 c3 0f d8 52") == create_NT_hashed_password_v1(
        PASSWORD)  # [MS-NLMP] page 73
    assert hex_to_byte("d8 72 62 b0 cd e4 b1 cb 74 99 be cc cd f1 07 84") == create_sessionbasekey(PASSWORD)
    assert hex_to_byte("67 c4 30 11 f3 02 98 a2 ad 35 ec e6 4f 16 33 1c 44 bd be d9 27 84 1f 94") == calc_resp(
        create_NT_hashed_password_v1(PASSWORD), SERVER_CHALLENGE)
    assert hex_to_byte("98 de f7 b8 7f 88 aa 5d af e2 df 77 96 88 a1 72 de f1 1c 7d 5c cd ef 13") == calc_resp(
        create_lm_hashed_password_v1(PASSWORD), SERVER_CHALLENGE)

    (NTLMv1Response, LMv1Response) = ntlm2sr_calc_resp(create_NT_hashed_password_v1(PASSWORD), SERVER_CHALLENGE,
                                                       CLIENT_CHALLENGE)
    assert hex_to_byte(
        "aa aa aa aa aa aa aa aa 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00") == LMv1Response  # [MS-NLMP] page 75
    assert hex_to_byte("75 37 f8 03 ae 36 71 28 ca 45 82 04 bd e7 ca f8 1e 97 ed 26 83 26 72 32") == NTLMv1Response

    # [MS-NLMP] page 76
    assert hex_to_byte("0c 86 8a 40 3b fd 7a 93 a3 00 1e f2 2e f0 2e 3f") == create_nt_hashed_password_v2(PASSWORD,
                                                                                                          USER,
                                                                                                          DOMAIN)
    ResponseKeyLM = ResponseKeyNT = create_nt_hashed_password_v2(PASSWORD, USER, DOMAIN)
    (NTLMv2Response, LMv2Response) = compute_response(ResponseKeyNT, ResponseKeyLM, SERVER_CHALLENGE, CLIENT_CHALLENGE,
                                                      TIME)
    assert hex_to_byte(
        "86 c3 50 97 ac 9c ec 10 25 54 76 4a 57 cc cc 19 aa aa aa aa aa aa aa aa") == LMv2Response  # [MS-NLMP] page 76
    assert create_ntlm_negotiate_message('DOMAIN\\User') == \
           "TlRMTVNTUAABAAAAB7IIogYABgAwAAAACAAIACgAAAAFASgKAAAAD1dTMDQyMzc4RE9NQUlO"

    # expected failure
    # According to the spec in section '3.3.2 NTLM v2 Authentication' the NTLMv2Response should be longer than the value
    # given on page 77 (this suggests a mistake in the spec)
    # [MS-NLMP] page 77
    assert hex_to_byte("68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c") == NTLMv2Response, \
        "\nExpected: 68 cd 0a b8 51 e5 1c 96 aa bc 92 7b eb ef 6a 1c\nActual:   {}".format(byte_to_hex(NTLMv2Response))
