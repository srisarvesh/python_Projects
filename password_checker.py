import requests
import hashlib
def request_api_data(query_char):
    url="https://api.pwnedpasswords.com/range/"+query_char
    res=requests.get(url)
    if(res.status_code!=200):
        raise RuntimeError(f"ChecktheAPI once{res.status_code}")
    else:
        return res
def get_password_leaks_count(hashes,hash_to_check):
    hashes=(line.split(":") for line in hashes.text.splitlines())
    for h,count in hashes:
        if h==hash_to_check:
            return count
    return 0
def pwned_api_check(password):

    hashs=hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    first5=hashs[:5]
    tail=hashs[5:]
    responce=request_api_data(first5)
    return get_password_leaks_count(responce,tail)
count=pwned_api_check("s123455678s")
if (count):
    print(f"Password is hacked{count}times")
else:
    print("It is not hacked")
