import base64
import re
from sage.all import *


## Decode the base64 PEM known parts and print it as a valid private key
part1 = "MIIJJAIBAAKCAgASUWUVXgOvRLJkI77YJ6BlG5t6en55ysW40HpawMJb9bTyWMInNIkWpL7+swa+eddajk+sL32Fkdf38eUAbq/y0y6T/LGlDLW9RJqEhAxx+fC62Zmu7tUA3DK3CS0LAhrd4oWdU8YE9LFhOID7StpmxaGdoFi8emZGuTXE0ooyG60KObs4dGV3Xbwq1xhM4iG9Drw94PwOlXS5UqDNfCcY0GlrorKsUSJwjNlkPIoos5FtR7KPRsau1+kd8aeCeAObkZciPRqLDojy3cVXZqKO6qpXHk2qfyEy1AKAFaNyt4sEt3WYex9qQg9a2W0w12zD01QZnJaKhTkMhdThLHrrBQsbBPQwsjcl7FwT0DQBOPZsas+kWUYbTr++WvKy1pB7j6eC4WUlFFKf3zQ2Z+aHXX0UmPPYDLdlJFgLbyrwEULxW7EOkTZt2IL3c4+ywkK0F6Ty4M+lzW/Wtj0ZcpAd9pudXEgXeCSUMJ6AlU0ckOl1WSpHzORHYZ9aPVt2Ertme7sU4XdJZLFOqXzqN1+Z96GdpUOptOmpeL2/sv/4816OlZdHOIjLErLv73CNhxSJ592zymSZesb0rSnH4T01ResFai6HLOMvE99ezt0lt73XwyRkMGRm0uW35Ir5rOioHkKVgas3dGjH8DED73WOrvt5p0BImSb9jyYzT9odZQIDAQABAoIB/0WfF5MewOJnN59kPPdRpU6kn0vkRtCg4N6PgntsJ0tdlV+F+mkIRALMJyHnTrqmXNzSB/9ogKwqpa68tKXwDM"
part2 = "YM4i/wJBudIGNGxwJRfOR9HUI2G/wchfC1772bxdFev5+0YMPiuBRnypiaHcf2/AAOmDMZJFyrTqrfy8jmxfdwKCAQAMVay1pGR15Pyz/AEqJvO4lrw09/BHA1xhDTc5uYzlChRuxJEn5ehmc1Lgbawr+jciSkfCnNkEueQYv0+EhPYFlJBsztrCJX3hzcVEU7qJLR4aAP6Px+G0Fd/kxQVbyrCvCKM1ptmpNPqYZE2IR5RiFzj4eD7rl1qEaBNIEdNs2VRMmsRwhrqIZcgRVbzcOf5cE3agelmTT/JeGFVFF+RiknxvhVcSScPKgsfdhpFwcYbeLqbLac7ZQcb1+Qz7XU"

redacted = base64.b64decode(part1+"==").hex() + 903*"00" + base64.b64decode(part2+"==").hex() + 585*"00"
print (re.sub("(.{100})", "\\1\n", redacted, 0, re.DOTALL))


## Retrived parameters from the above result

n = 0x125165155e03af44b26423bed827a0651b9b7a7a7e79cac5b8d07a5ac0c25bf5b4f258c227348916a4befeb306be79d75a8e4fac2f7d8591d7f7f1e5006eaff2d32e93fcb1a50cb5bd449a84840c71f9f0bad999aeeed500dc32b7092d0b021adde2859d53c604f4b1613880fb4ada66c5a19da058bc7a6646b935c4d28a321bad0a39bb387465775dbc2ad7184ce221bd0ebc3de0fc0e9574b952a0cd7c2718d0696ba2b2ac5122708cd9643c8a28b3916d47b28f46c6aed7e91df1a78278039b9197223d1a8b0e88f2ddc55766a28eeaaa571e4daa7f2132d4028015a372b78b04b775987b1f6a420f5ad96d30d76cc3d354199c968a85390c85d4e12c7aeb050b1b04f430b23725ec5c13d0340138f66c6acfa459461b4ebfbe5af2b2d6907b8fa782e1652514529fdf343667e6875d7d1498f3d80cb76524580b6f2af01142f15bb10e91366dd882f7738fb2c242b417a4f2e0cfa5cd6fd6b63d1972901df69b9d5c4817782494309e80954d1c90e975592a47cce447619f5a3d5b7612bb667bbb14e1774964b14ea97cea375f99f7a19da543a9b4e9a978bdbfb2fff8f35e8e9597473888cb12b2efef708d871489e7ddb3ca64997ac6f4ad29c7e13d3545eb056a2e872ce32f13df5ecedd25b7bdd7c32464306466d2e5b7e48af9ace8a81e429581ab377468c7f03103ef758eaefb79a740489926fd8f26334fda1d65
e = 0x10001
d_upper_bits_504 = 0x459f17931ec0e267379f643cf751a54ea49f4be446d0a0e0de8f827b6c274b5d955f85fa69084402cc2721e74ebaa65cdcd207ff6880ac2aa5aebcb4a5f00c
q_lower_bits_512 = 0x60ce22ff0241b9d206346c702517ce47d1d42361bfc1c85f0b5efbd9bc5d15ebf9fb460c3e2b81467ca989a1dc7f6fc000e983319245cab4eaadfcbc8e6c5f77
dp_upper_bits_1528 = 0x0c55acb5a46475e4fcb3fc012a26f3b896bc34f7f047035c610d3739b98ce50a146ec49127e5e8667352e06dac2bfa37224a47c29cd904b9e418bf4f8484f60594906ccedac2257de1cdc54453ba892d1e1a00fe8fc7e1b415dfe4c5055bcab0af08a335a6d9a934fa98644d884794621738f8783eeb975a8468134811d36cd9544c9ac47086ba8865c81155bcdc39fe5c1376a07a59934ff25e18554517e462927c6f85571249c3ca82c7dd8691707186de2ea6cb69ced941c6f5f90cfb5d
dp_upper_bits_1512 = 0x0c55acb5a46475e4fcb3fc012a26f3b896bc34f7f047035c610d3739b98ce50a146ec49127e5e8667352e06dac2bfa37224a47c29cd904b9e418bf4f8484f60594906ccedac2257de1cdc54453ba892d1e1a00fe8fc7e1b415dfe4c5055bcab0af08a335a6d9a934fa98644d884794621738f8783eeb975a8468134811d36cd9544c9ac47086ba8865c81155bcdc39fe5c1376a07a59934ff25e18554517e462927c6f85571249c3ca82c7dd8691707186de2ea6cb69ced941c6f5f90c


"""
FINDING P0 (the last 512 bits of p)
"""
# N = p0 * q0 \mod 2^512 ottengo gli ultimo 512 bit di p
temp_mod = 2**512
N_mod = n % temp_mod
q0_inverse = inverse_mod((q_lower_bits_512 % temp_mod), temp_mod)
p0 = (N_mod * q0_inverse) % temp_mod

assert (p0 * q_lower_bits_512) % temp_mod == N_mod

p = 1
# computing the possible guesses for dp and try to discover p
for k in range(1,e):
    e_inverse = inverse_mod(e, temp_mod)
    dp_lower_bits = ((1 + k*(p0-1))*e_inverse) % (temp_mod)
    for unknown_value in range(0,256):
        dp_lower = dp_lower_bits + unknown_value*(2**512)
        dp = dp_upper_bits_1528*(2**520) + dp_lower
        result = (e*dp -1)/k + 1
        if n % int(result) == 0 and is_prime(int(result)):
            p = int(result)
            break
    if p != 1:
        break

if p != 1:
    print("Parameter found. All the retrived parameters are:")

    q = n // p
    phiN = (p-1)*(q-1)
    d = inverse_mod(e, phiN)

    print(f'n = {n}')
    print(f'p = {p}')
    print(f'q = {q}')
    print(f'd = {d}')
    print(f'e = {e}')


"""
In order to create the private key in PEM format

from Crypto.PublicKey import RSA

key = RSA.construct((n,e,d,p,q))
pem = key.export_key('PEM')
print(pem.decode())

"""