from pypacker import ppcap
from pypacker.layer12 import ethernet
from pypacker.layer12 import linuxcc
from pypacker.layer3 import ip
from pypacker.layer3 import icmp
from pypacker.layer4 import tcp
from pypacker.layer4 import udp
from pypacker import pypacker
from datetime import datetime
import pcapy
import getopt
import time
import sys
import os
import signal
import untangle
import json
import struct
from pathlib import Path

"""
Author: Nikolai Tschacher
Date: March 2021

Allows to fingerprint an incoming TCP/IP connection.

Several fields such as TCP Options or TCP Window Size 
or IP Fragment Flag depend heavily on the OS type and version.

Some code has been taken from: https://github.com/xnih/satori
However, the codebase of github.com/xnih/satori was quite frankly 
a huge mess (randomly failing code segments and capturing the Errors, not good). 
"""

interface = None
verbose = False
fingerprints = {}

def signal_handler(sig, frame):
  with open('fingerprints.json', 'w') as fp:
    json.dump(fingerprints, fp, indent=2, sort_keys=False)
  sys.exit(0)

signal.signal(signal.SIGINT, signal_handler) # ctlr + c
signal.signal(signal.SIGTSTP, signal_handler) # ctlr + z

def decodeTCPOptions(opts):
  res = ''
  mss = 0
  tcpTimeStampEchoReply = ''
  tcpTimeStamp = ''

  for i in opts:
    if i.type == 0: # End of options list
      res = res + 'E,'
    elif i.type == 1: # No operation
      res = res + 'N,'
    elif i.type == 2: # Maximum segment size
      mss = struct.unpack('!h',i.body_bytes)[0]
      res = res + 'M' + str(mss) + ','
    elif i.type == 3: # Window scale
      x = struct.unpack('!b',i.body_bytes)[0]
      res = res + 'W' + str(x) + ','
    elif i.type == 4: # Selective Acknowledgement permitted
      res = res + 'S,'
    elif i.type == 5: # Selective ACKnowledgement (SACK)
      res = res + 'K,' 
    elif i.type == 6:
      res = res + 'J,'
    elif i.type == 7:
      res = res + 'F,'  
      #print("Options Echo (need to compute?):  %s" % (i.body_bytes))
    elif i.type == 8:
      res = res + 'T,'
      tcpTimeStamp = struct.unpack('!I',i.body_bytes[0:4])[0]
      tcpTimeStampEchoReply = struct.unpack('!I',i.body_bytes[4:8])[0] 
    elif i.type == 9:
      res = res + 'P,'
    elif i.type == 10:
      res = res + 'R,'
    else:
      res = res + 'U,'
      print('unknown TCP Options')

  return(res, tcpTimeStamp, tcpTimeStampEchoReply, mss)


def tcpProcess(pkt, layer, ts):
  """
  Understand this: https://www.keycdn.com/support/tcp-flags

  from src -> dst, SYN
  from dst -> src, SYN-ACK
  from src -> dst, ACK

  Capture SYN-ACK: 

  tcpdump -ni <device> -c 25 'tcp[tcpflags] & (tcp-ack | tcp-syn) !=0 '
  """
  if layer == 'eth':
    src_mac = pkt[ethernet.Ethernet].src_s
  else:
    #fake filler mac for all the others that don't have it, may have to add some elif above
    src_mac = '00:00:00:00:00:00'

  ip4 = pkt.upper_layer
  tcp1 = pkt.upper_layer.upper_layer

  # SYN (1 bit): Synchronize sequence numbers. Only the first packet sent from each
  # end should have this flag set. Some other flags and fields change meaning
  # based on this flag, and some are only valid when it is set, and others when it is clear.
  if tcp1.flags & tcp.TH_SYN:
    label = ''
    if tcp1.flags & tcp.TH_SYN:
      label = 'SYN'
    if (tcp1.flags & tcp.TH_SYN) and (tcp1.flags & tcp.TH_ACK):
      label = 'SYN+ACK'

    print("%d: %s:%s -> %s:%s [%s]" % (ts, pkt[ip.IP].src_s, pkt[tcp.TCP].sport,
        pkt[ip.IP].dst_s, pkt[tcp.TCP].dport, label))

    [ipVersion, ipHdrLen] = computeIP(ip4.v_hl)
    [ethTTL, ttl] = computeNearTTL(ip4.ttl)
    [df, mf, offset] = computeIPOffset(ip4.off)

    [tcpOpts, tcpTimeStamp, tcpTimeStampEchoReply, mss] = decodeTCPOptions(tcp1.opts)

    if verbose:
      print('IP version={}, header length={}, TTL={}, df={}, mf={}, offset={}'.format(
        ipVersion,
        ipHdrLen,
        ip4.ttl,
        df,
        mf,
        offset,
      ))
      print('TCP window size={}, flags={}, ack={}, header length={}, urp={}, options={}, time stamp={}, timestamp echo reply = {}, MSS={}'.format(
        tcp1.win,
        tcp1.flags,
        tcp1.ack,
        tcp1.off_x2,
        tcp1.urp,
        tcpOpts,
        tcpTimeStamp,
        tcpTimeStampEchoReply,
        mss
      ))
    
    if label == 'SYN':
      key = '{}:{}'.format(pkt[ip.IP].src_s, pkt[tcp.TCP].sport)
      fingerprints[key] = {
        'ts': ts,
        'src_ip': pkt[ip.IP].src_s,
        'dst_ip': '{}'.format(pkt[ip.IP].dst_s),
        'dst_port': '{}'.format(pkt[tcp.TCP].dport),
        'ip_df': df,
        'ip_mf': mf,
        'tcp_window_size': tcp1.win,
        'tcp_flags': tcp1.flags,
        'tcp_ack': tcp1.ack,
        'tcp_header_length': tcp1.off_x2,
        'tcp_urp': tcp1.urp,
        'tcp_options': tcpOpts,
        'tcp_timestamp_echo_reply': tcpTimeStampEchoReply,
        'tcp_mss': mss
      }
    print('---------------------------------')


def computeIP(info):
  ipVersion = int('0x0' + hex(info)[2], 16)
  ipHdrLen = int('0x0' + hex(info)[3], 16) * 4  
  return [ipVersion, ipHdrLen]


def computeNearTTL(info):
  if (info>0) and (info<=16):
    ttl = 16
    ethTTL = 16
  elif (info>16) and (info<=32):
    ttl = 32 
    ethTTL = 43
  elif (info>32) and (info<=60):
    ttl = 60 #unlikely to find many of these anymore
    ethTTL = 64
  elif (info>60) and (info<=64):
    ttl = 64
    ethTTL = 64
  elif (info>64) and (info<=128):
    ttl = 128
    ethTTL = 128
  elif (info>128):
    ttl = 255
    ethTTL = 255
  else:
    ttl = info
    ethTTL = info
  return [ethTTL, ttl]


def computeIPOffset(info):
  # need to see if I can find a way to import these from ip.py as they are already defined there.
  # Fragmentation flags (ip_off)
  IP_RF = 0x4   # reserved
  IP_DF = 0x2   # don't fragment
  IP_MF = 0x1   # more fragments (not last frag)

  res = 0
  df = 0
  mf = 0

  flags = (info & 0xE000) >> 13
  offset = (info & ~0xE000)

  if (flags & IP_RF) > 0:
    res = 1
  if (flags & IP_DF) > 0:
    df = 1
  if (flags & IP_MF) > 0:
    mf = 1

  return [df, mf, offset]


def usage():
  print("""
    -i, --interface   interface to listen to; example: -i eth0
    -l, --log         log file to write output to; example -l output.txt (not implemented yet)
    -v, --verbose     verbose logging, mostly just telling you where/what we're doing, not recommended if want to parse output typically""")

def main():
  #override some warning settings in pypacker.  May need to change this to .CRITICAL in the future, but for now we're trying .ERROR
  #without this when parsing http for example we get "WARNINGS" when packets aren't quite right in the header.
  logger = pypacker.logging.getLogger("pypacker")
  pypacker.logger.setLevel(pypacker.logging.ERROR)

  counter = 0
  startTime = time.time()

  print('listening on interface {}'.format(interface))

  try:
    preader = pcapy.open_live(interface, 65536, False, 1)
    preader.setfilter('tcp port 80 or tcp port 443')
  except Exception as e:
    print(e, end='\n', flush=True)
    sys.exit(1)

  while True:
    try:
      counter = counter + 1
      (header, buf) = preader.next()
      ts = header.getts()[0]

      tcpPacket = False
      pkt = None
      layer = None

      # try to determine what type of packets we have, there is the chance that 0x800
      #  may be in the spot we're checking, may want to add better testing in future
      eth = ethernet.Ethernet(buf)
      if hex(eth.type) == '0x800':
        layer = 'eth'
        pkt = eth

        if (eth[ethernet.Ethernet, ip.IP, tcp.TCP] is not None):
          tcpPacket = True

      lcc = linuxcc.LinuxCC(buf)
      if hex(lcc.type) == '0x800':
        layer = 'lcc'
        pkt = lcc

        if (lcc[linuxcc.LinuxCC, ip.IP, tcp.TCP] is not None):
          tcpPacket = True

      if tcpPacket and pkt and layer:
        tcpProcess(pkt, layer, ts)

    except (KeyboardInterrupt, SystemExit):
      raise
    except Exception as e:
      print(str(e))

  endTime = time.time()
  totalTime = endTime - startTime

  if verbose:
    print ('Total Time: %s, Total Packets: %s, Packets/s: %s' % (totalTime, counter, counter / totalTime ))

try:
  opts, args = getopt.getopt(sys.argv[1:], "i:v:", ['interface=', 'verbose',])
  proceed = False

  for opt, val in opts:
    if opt in ('-i', '--interface'):
      interface = val
      proceed = True
    if opt in ('-v', '--verbose'):
      verbose = True

  if (__name__ == '__main__') and proceed:
    main()
  else:
    print('Need to provide a pcap to read in or an interface to watch', end='\n', flush=True)
    usage()
except getopt.error:
  usage()
