from pprint import pp

from .models import GSAuthToken, GSAuthTokens
from .auth import  main

m = main()
a = m[0]
def parse_tokens(data: dict):
    for k, v in data.items():
        print(f"{k}: {v['expiry']}\n{v['token']}")

tokens = m[1]['t'] if isinstance(m[1], dict) else m[1][0]['t']
#parse_tokens(tokens)

x = m[1][1]
