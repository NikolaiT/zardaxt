import requests

# API client implementation
counter = {
    "hits": 0,
    "data": {},
}

def incr(api, ip, push_after=50):
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
        response = requests.post('https://dune.incolumitas.com/update?key=ggbbKKss', json=payload)
        print(response)