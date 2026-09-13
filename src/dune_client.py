"""
Dune usage client.

Counts client IP hits and ships them to dune in gzipped batches from a
background thread.

The previous implementation pushed once every `push_after` hits from inside the
caller's thread. That made the request rate drive the push rate - the
tcp_ip_fingerprint_public deployment sent 5244 POSTs a day to report 1.07M hits,
about 204 hits per request - and it made every 200th API call wait on a TLS
handshake and a round trip to dune. It also zeroed the counters before the POST
and never retried, so anything dune failed to accept was gone for good.
"""
import atexit
import gzip
import json
import os
import random
import sys
import threading
import urllib.request

# How long hits accumulate before they are shipped.
FLUSH_INTERVAL_S = 300
# Safety valve for traffic spikes, so the buffer cannot grow without bound
# between ticks. Kept well under dune's 32MB body limit: this many IPs serialize
# to roughly 6MB, and a push refused for being too large would retry forever.
MAX_BUFFERED_IPS = 250000
# A failed push is merged back and retried on the next tick, but not forever:
# past this many buffered IPs dune has been unreachable long enough that the
# backlog costs more than the counts are worth.
MAX_RETAINED_IPS = 2000000
DEFAULT_ENDPOINT = 'https://dune.incolumitas.com/update'
# tcp_ip_fingerprint_public is a public API on dune, so an unconfigured
# deployment still reports under the shared key rather than silently buffering.
DEFAULT_API_KEY = 'DunePublicAPIKey'


def _log(message):
    print('[dune_client] {}'.format(message), file=sys.stderr)


class DuneClient:
    """Batches hit counts for one API and ships them on a timer."""

    def __init__(self, api, api_key=None, endpoint=DEFAULT_ENDPOINT,
                 flush_interval=FLUSH_INTERVAL_S):
        self.api = api
        self.api_key = os.environ.get('DUNE_API_KEY', DEFAULT_API_KEY) if api_key is None else api_key
        self.endpoint = endpoint
        self.flush_interval = flush_interval
        self.max_buffered_ips = MAX_BUFFERED_IPS

        self._lock = threading.Lock()
        # Serializes pushes: an overflow flush and the shutdown flush can be
        # raised at the same moment, and stop() has to wait for both rather than
        # return while a batch is still on the wire.
        self._flush_lock = threading.Lock()
        self._hits = 0
        self._data = {}
        self._dropped = 0
        self._wake = threading.Event()
        self._stopped = False

        self._thread = threading.Thread(target=self._loop, name='dune-flush', daemon=True)
        self._thread.start()
        atexit.register(self.stop)

    def incr(self, ip):
        """Counts one hit. Does no IO, so the caller never waits on the network."""
        if not ip or ip in ('127.0.0.1', '0.0.0.0'):
            return

        with self._lock:
            self._hits += 1
            self._data[ip] = self._data.get(ip, 0) + 1
            overflowing = len(self._data) >= self.max_buffered_ips

        if overflowing:
            self._wake.set()

    def flush(self):
        """Ships everything counted so far."""
        with self._flush_lock:
            with self._lock:
                hits, data = self._hits, self._data
                self._hits, self._data = 0, {}

            if not hits:
                return
            if not self.api_key:
                # Nowhere to send it, but keep counting rather than throw the
                # window away.
                self._put_back(hits, data)
                return

            try:
                self._post(hits, data)
            except Exception as err:
                _log('push failed, retrying with the next batch: {}'.format(err))
                self._put_back(hits, data)

    def stop(self):
        """Stops the flush loop and ships whatever is left."""
        if self._stopped:
            return
        self._stopped = True
        self._wake.set()
        self.flush()

    def _loop(self):
        # The first interval is randomized so a fleet restarted together does
        # not line every worker up on the same boundary.
        delay = random.uniform(0, self.flush_interval)
        while not self._stopped:
            woken = self._wake.wait(delay)
            if self._stopped:
                return
            if woken:
                self._wake.clear()
            delay = self.flush_interval
            self.flush()

    def _put_back(self, hits, data):
        """Returns an unsent batch to the buffer so the next tick carries it."""
        with self._lock:
            if len(self._data) + len(data) > MAX_RETAINED_IPS:
                self._dropped += hits
                _log('dune unreachable, dropped a backlog of {} hits ({} total)'.format(
                    hits, self._dropped))
                return

            self._hits += hits
            # Merge the smaller side into the larger; a backlog can be far
            # bigger than what has accumulated since it was taken.
            if len(self._data) > len(data):
                for ip, count in data.items():
                    self._data[ip] = self._data.get(ip, 0) + count
                return
            for ip, count in self._data.items():
                data[ip] = data.get(ip, 0) + count
            self._data = data

    def _post(self, hits, data):
        payload = gzip.compress(json.dumps({
            'api': self.api,
            'hits': hits,
            'data': data,
        }).encode('utf-8'))

        request = urllib.request.Request(
            '{}?key={}'.format(self.endpoint, self.api_key),
            data=payload,
            headers={
                'Content-Type': 'application/json',
                'Content-Encoding': 'gzip',
            },
            method='POST',
        )
        with urllib.request.urlopen(request, timeout=30) as response:
            response.read()
            if response.status != 200:
                raise RuntimeError('dune returned {}'.format(response.status))


_clients = {}
_clients_lock = threading.Lock()


def incr(api, ip, push_after=None):
    """
    Counts one hit against `api`.

    `push_after` is accepted so existing callers keep working, but it is ignored:
    batches are shipped on a timer now, not on a hit count.
    """
    with _clients_lock:
        client = _clients.get(api)
        if client is None:
            client = DuneClient(api)
            _clients[api] = client
    client.incr(ip)
