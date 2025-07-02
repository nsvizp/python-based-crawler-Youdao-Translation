#!/usr/bin/python3
# -*- coding:utf-8 -*-
# @Author : myxfc
#更新时间 2025/03/21 目前稳定可用


from urllib.parse import urlencode, quote_plus
import requests
import hashlib
import time
import json
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import base64



# 生成Key和IV时修正
def md5_hash(s):
    md5 = hashlib.md5()
    md5.update(s.encode('utf-8'))
    return md5.digest()  # 确保返回bytes类型

secretKey_param = "SRz6r3IGA6lj9i5zW0OYqgVZOtLDQe3e" #翻译失败很可能是三个key值的改变
aes_iv_str = "ydsecret://query/iv/C@lZe2YzHtZ2CYgaXKSVfsb7Y4QWHjITPPZ0nQp87fBeJ!Iv6v^6fvi2WN@bYpJ4"
aes_key_str = "ydsecret://query/key/B*RGygVywfNBwpmBaZg*WT7SIOUP2T0C9WHMZN39j^DAdaZhAnxvGcCY6VYFwnHl"
# secretKey = secretKey_str
iv = md5_hash(aes_iv_str)
key = md5_hash(aes_key_str)


# 解密函数
def decrypt(ciphertext):
    # 处理URL安全的Base64并移除干扰字符
    ciphertext = ciphertext.replace('-', '+').replace('_', '/').replace(' ', '')
    try:
        cipher_bytes = base64.b64decode(ciphertext, validate=True)
        aes_cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = aes_cipher.decrypt(cipher_bytes)
        return unpad(decrypted, AES.block_size).decode('utf-8')
    except (ValueError, TypeError) as e:
        print(f"解密失败: {str(e)}")
        return None


# 请求参数
url = 'https://dict.youdao.com/webtranslate'
headers = {

    "Accept": "application/json, text/plain, */*","accept-encoding":"gzip, deflate, br, zstd","accept-language":"zh-CN,zh;q=0.9,en;q=0.8,en-GB;q=0.7,en-US;q=0.6",
    "connection":"keep-alive",
    # "content-type":"application/x-www-form-urlencoded",
    "Cookie": "OUTFOX_SEARCH_USER_ID=-57891657@125.86.188.112; OUTFOX_SEARCH_USER_ID_NCOO=118049373.81209917; _uetsid=54ad8ce0060011f0a15787a3554a5b20; _uetvid=54ade1c0060011f09c2211cd64baad7a; DICT_DOCTRANS_SESSION_ID=ZDlmNTMyNDYtOTdjZS00Y2MzLTkwZDktN2IzY2Q4NjM5MDVj",
    "host":"dict.youdao.com",
    "origin":"https://fanyi.youdao.com",
    "referer":"https://fanyi.youdao.com/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.0.0"
}

mystic_time = str(int(time.time() * 1000))
# mystic_time = time.time()
# key_param = "Vy4EQ1uwPkUoqvcP1nIu6WiAjxFeA3Y3"

# 签名生成修正
# sign_str = f"client=fanyideskweb&mysticTime={mystic_time}&product=webfanyi&key={key_param}"
sign_str = f"client=fanyideskweb&mysticTime={mystic_time}&product=webfanyi&key={secretKey_param}"
# sign_str = f'client=fanyideskweb&mysticTime={mystic_time}&product=webfanyi&key=Vy4EQ1uwPkUoqvcP1nIu6WiAjxFeA3Y3'
sign = hashlib.md5(sign_str.encode()).hexdigest()
# def get_sign():
#     e = f'client=fanyideskweb&mysticTime={timestamp}&product=webfanyi&key=Vy4EQ1uwPkUoqvcP1nIu6WiAjxFeA3Y3'
#     sign = hashlib.md5(e.encode()).hexdigest()
#     return sign

data = {
    "i": "happy ",  # 示例翻译文本
    "from": "auto",
    "to": "",
    "useTerm": "false",
    "dictResult": "true",
    "keyid": "webfanyi",
    "sign": sign,
    "client": "fanyideskweb",
    "product": "webfanyi",
    "appVersion": "1.0.0",
    "vendor": "web",
    "pointParam": "client,mysticTime,product",
    "mysticTime": mystic_time,
    "keyfrom": "fanyi.web",
    "mid": "1",
    "screen": "1",
    "model": "1",
    "network": "wifi",
    "abtest": "0",
    "yduuid": "abcdefg"
}
# def custom_encoder(s):
#     # 分步处理特殊字符
#     # encoded = quote_plus(str(s), safe='')  # 基础编码
#     encoded = encoded.replace(' ', '%0A')  # 空格→%0A
#     return encoded
# form_data = urlencode(data, quote_via=custom_encoder, doseq=True)
# print("最终请求体:", form_data)

# 发送请求并处理响应
try:
    response = requests.post(url, headers=headers, data=data, timeout=10)
    response.raise_for_status()  # 自动处理HTTP错误

    encrypted_data = response.text.strip()
    print("原始响应:", encrypted_data)

    # 直接解密原始响应
    decrypted_text = decrypt(encrypted_data)
    if decrypted_text:
        print("\n翻译结果:")
        print(json.dumps(json.loads(decrypted_text), indent=2, ensure_ascii=False))
    else:
        print("解密失败，请检查密钥或响应数据")

except requests.exceptions.RequestException as e:
    print(f"请求异常: {str(e)}")
except json.JSONDecodeError:
    print("响应不是有效JSON格式")
