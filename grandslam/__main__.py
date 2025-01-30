from pprint import pp

from .auth import main

m = main()
pp(list(m[1]['t'].keys()) if isinstance(m[1], dict) else list(m[1][0]['t'].keys()))
x = m[1][1]
