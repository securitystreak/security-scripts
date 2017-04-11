from Crypto.Cipher import ARC4
key = “”.encode(“hex”)
response = “”
enc = ARC4.new(key)
response = response.decode(“base64”)
print enc.decrypt(response)
