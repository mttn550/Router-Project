from dns import resolver

r = resolver.Resolver()

ans = r.query('eranbi.net')
print(ans.response)