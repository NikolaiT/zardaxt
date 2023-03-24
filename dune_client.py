import requests
import os

# API client implementation
counter = {
    "hits": 0,
    "data": {},
}


def incr(api, ip, push_after=500):
    global counter
    counter['hits'] += 1

    if ip in counter['data']:
        counter['data'][ip] += 1
    else:
        counter['data'][ip] = 0

    if counter['hits'] > push_after:
        payload = {
            'api': api,
            'hits': counter['hits'],
            'data': counter['data'],
        }
        counter = {
            'hits': 0,
            'data': {},
        }
        api_key = os.environ.get('DUNE_API_KEY', 'DunePublicAPIKey')
        api_url = 'https://dune.incolumitas.com/update?key={}'.format(api_key)
        response = requests.post(api_url, json=payload)
