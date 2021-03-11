import struct

"""
Parse TCP options.

TCP options is probably the most valueable source of entropy in
TCP SYN packets.

https://www.iana.org/assignments/tcp-parameters/tcp-parameters.xhtml
"""

# TCP Options (opt_type) - http://www.iana.org/assignments/tcp-parameters
TCP_OPT_EOL		= 0		# end of option list
TCP_OPT_NOP		= 1		# no operation
TCP_OPT_MSS		= 2		# maximum segment size
TCP_OPT_WSCALE		= 3		# window scale factor, RFC 1072
TCP_OPT_SACKOK		= 4		# SACK permitted, RFC 2018
TCP_OPT_SACK		= 5		# SACK, RFC 2018
TCP_OPT_ECHO		= 6		# echo (obsolete), RFC 1072
TCP_OPT_ECHOREPLY	= 7		# echo reply (obsolete), RFC 1072
TCP_OPT_TIMESTAMP	= 8		# timestamps, RFC 1323
TCP_OPT_POCONN		= 9		# partial order conn, RFC 1693
TCP_OPT_POSVC		= 10		# partial order service, RFC 1693
TCP_OPT_CC		= 11		# connection count, RFC 1644
TCP_OPT_CCNEW		= 12		# CC.NEW, RFC 1644
TCP_OPT_CCECHO		= 13		# CC.ECHO, RFC 1644
TCP_OPT_ALTSUM		= 14		# alt checksum request, RFC 1146
TCP_OPT_ALTSUMDATA	= 15		# alt checksum data, RFC 1146
TCP_OPT_SKEETER		= 16		# Skeeter
TCP_OPT_BUBBA		= 17		# Bubba
TCP_OPT_TRAILSUM	= 18		# trailer checksum
TCP_OPT_MD5		= 19		# MD5 signature, RFC 2385
TCP_OPT_SCPS		= 20		# SCPS capabilities
TCP_OPT_SNACK		= 21		# selective negative acks
TCP_OPT_REC		= 22		# record boundaries
TCP_OPT_CORRUPT		= 23		# corruption experienced
TCP_OPT_SNAP		= 24		# SNAP
TCP_OPT_TCPCOMP		= 26		# TCP compression filter
TCP_OPT_MAX		= 27 # Quick-Start Response
TCP_OPT_USRTO = 28 # User Timeout Option (also, other known unauthorized use) [***][1]	[RFC5482]
TCP_OPT_AUTH = 29 # TCP Authentication Option (TCP-AO)	[RFC5925]
TCP_OPT_MULTIPATH = 30 # Multipath TCP (MPTCP)
TCP_OPT_FASTOPEN = 34 # TCP Fast Open Cookie	[RFC7413]
TCP_OPY_ENCNEG = 69 # Encryption Negotiation (TCP-ENO)	[RFC8547]
TCP_OPT_EXP1 = 253 # RFC3692-style Experiment 1 (also improperly used for shipping products) 
TCP_OPT_EXP2 = 254 # RFC3692-style Experiment 2 (also improperly used for shipping products)

def decodeTCPOptions(opts):
  """
  Decodes TCP options into a readable string.
  """
  res = ''
  mss = 0
  tcpTimeStampEchoReply = ''
  tcpTimeStamp = ''
  windowScaling = None

  for i in opts:
    if i.type == TCP_OPT_EOL: # End of options list
      res = res + 'E,'
    elif i.type == TCP_OPT_NOP: # No operation
      res = res + 'N,'
    elif i.type == TCP_OPT_MSS: # Maximum segment size
      mss = struct.unpack('!h',i.body_bytes)[0]
      res = res + 'M' + str(mss) + ','
    elif i.type == TCP_OPT_WSCALE: # Window scaling
      windowScaling = struct.unpack('!b',i.body_bytes)[0]
      res = res + 'W' + str(windowScaling) + ','
    elif i.type == TCP_OPT_SACKOK: # Selective Acknowledgement permitted
      res = res + 'S,'
    elif i.type == TCP_OPT_SACK: # Selective ACKnowledgement (SACK)
      res = res + 'K,'
    elif i.type == TCP_OPT_ECHO:
      res = res + 'J,'
    elif i.type == TCP_OPT_ECHOREPLY:
      res = res + 'F,'  
      #print("Options Echo (need to compute?):  %s" % (i.body_bytes))
    elif i.type == TCP_OPT_TIMESTAMP:
      res = res + 'T,'
      tcpTimeStamp = struct.unpack('!I',i.body_bytes[0:4])[0]
      tcpTimeStampEchoReply = struct.unpack('!I',i.body_bytes[4:8])[0] 
    elif i.type == TCP_OPT_POCONN:
      res = res + 'P,'
    elif i.type == TCP_OPT_POSVC:
      res = res + 'R,'
    else: # unknown TCP option. Just store the opt_type
      res = res + 'U' + str(i.type) + ','

  return(res, tcpTimeStamp, tcpTimeStampEchoReply, mss, windowScaling)