import struct
from zardaxt_logging import log

"""
Parse TCP options.

TCP options is probably the most valuable source of entropy in
TCP SYN packets.

https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
"""

# TCP Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
TCP_OPT_EOL = 0		# end of option list
TCP_OPT_NOP = 1		# no operation
TCP_OPT_MSS = 2		# maximum segment size
TCP_OPT_WSCALE = 3		# window scale factor, RFC 1072
TCP_OPT_SACKOK = 4		# SACK permitted, RFC 2018
TCP_OPT_SACK = 5		# SACK, RFC 2018
TCP_OPT_ECHO = 6		# echo (obsolete), RFC 1072
TCP_OPT_ECHOREPLY = 7		# echo reply (obsolete), RFC 1072
TCP_OPT_TIMESTAMP = 8		# timestamps, RFC 1323
TCP_OPT_POCONN = 9		# partial order conn, RFC 1693
TCP_OPT_POSVC = 10		# partial order service, RFC 1693
TCP_OPT_CC = 11		# connection count, RFC 1644
TCP_OPT_CCNEW = 12		# CC.NEW, RFC 1644
TCP_OPT_CCECHO = 13		# CC.ECHO, RFC 1644
TCP_OPT_ALTSUM = 14		# alt checksum request, RFC 1146
TCP_OPT_ALTSUMDATA = 15		# alt checksum data, RFC 1146
TCP_OPT_SKEETER = 16		# Skeeter
TCP_OPT_BUBBA = 17		# Bubba
TCP_OPT_TRAILSUM = 18		# trailer checksum
TCP_OPT_MD5 = 19		# MD5 signature, RFC 2385
TCP_OPT_SCPS = 20		# SCPS capabilities
TCP_OPT_SNACK = 21		# selective negative acks
TCP_OPT_REC = 22		# record boundaries
TCP_OPT_CORRUPT = 23		# corruption experienced
TCP_OPT_SNAP = 24		# SNAP
TCP_OPT_TCPCOMP = 26		# TCP compression filter
TCP_OPT_MAX = 27  # Quick-Start Response
# User Timeout Option (also, other known unauthorized use) [***][1]	[RFC5482]
TCP_OPT_USRTO = 28
TCP_OPT_AUTH = 29  # TCP Authentication Option (TCP-AO)	[RFC5925]
TCP_OPT_MULTIPATH = 30  # Multipath TCP (MPTCP)
TCP_OPT_FASTOPEN = 34  # TCP Fast Open Cookie	[RFC7413]
TCP_OPY_ENCNEG = 69  # Encryption Negotiation (TCP-ENO)	[RFC8547]
# RFC3692-style Experiment 1 (also improperly used for shipping products)
TCP_OPT_EXP1 = 253
# RFC3692-style Experiment 2 (also improperly used for shipping products)
TCP_OPT_EXP2 = 254


def decode_tcp_options(opts):
    """
    Decodes TCP options into a readable string.

    [(2, b'\x05\xb4'), (1, b''), (3, b'\x06'), (1, b''), (1, b''),
      (8, b'3.S\xa8\x00\x00\x00\x00'), (4, b''), (0, b''), (0, b'')]
    """
    str_opts = ''
    mss = 0
    timestamp_echo_reply = ''
    timestamp = ''
    window_scaling = None

    for opt in opts:
        option_type, option_value = opt
        if option_type == TCP_OPT_EOL:  # End of options list
            str_opts = str_opts + 'E,'
        elif option_type == TCP_OPT_NOP:  # No operation
            str_opts = str_opts + 'N,'
        elif option_type == TCP_OPT_MSS:  # Maximum segment size
            try:
                mss = struct.unpack('!h', option_value)[0]
                str_opts = str_opts + 'M' + str(mss) + ','
            except Exception as e:
                log('failed to parse TCP_OPT_MSS: {}'.format(
                    str(e)), 'zardaxt_tcp_options', level='ERROR')
        elif option_type == TCP_OPT_WSCALE:  # Window scaling
            window_scaling = struct.unpack('!b', option_value)[0]
            str_opts = str_opts + 'W' + str(window_scaling) + ','
        elif option_type == TCP_OPT_SACKOK:  # Selective Acknowledgement permitted
            str_opts = str_opts + 'S,'
        elif option_type == TCP_OPT_SACK:  # Selective ACKnowledgement (SACK)
            str_opts = str_opts + 'K,'
        elif option_type == TCP_OPT_ECHO:
            str_opts = str_opts + 'J,'
        elif option_type == TCP_OPT_ECHOREPLY:
            str_opts = str_opts + 'F,'
        elif option_type == TCP_OPT_TIMESTAMP:
            try:
                str_opts = str_opts + 'T,'
                timestamp = struct.unpack('!I', option_value[0:4])[0]
                timestamp_echo_reply = struct.unpack(
                    '!I', option_value[4:8])[0]
            except Exception as e:
                log('failed to parse TCP_OPT_TIMESTAMP: {}'.format(
                    str(e)), 'zardaxt_tcp_options', level='ERROR')
        elif option_type == TCP_OPT_POCONN:
            str_opts = str_opts + 'P,'
        elif option_type == TCP_OPT_POSVC:
            str_opts = str_opts + 'R,'
        else:  # unknown TCP option. Just store the opt_type
            str_opts = str_opts + 'U' + str(option_type) + ','

    return (str_opts, timestamp, timestamp_echo_reply, mss, window_scaling)
