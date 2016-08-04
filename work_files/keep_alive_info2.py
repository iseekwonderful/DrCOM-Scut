source = ("07013000040c2000e1d9473a010000004439d8edac314b070a635f1beeb20449b0820060000000000000000000000000")\
    .decode("hex")
info_1 = source[16:]
info_2 = [0 for _ in range(16)]
print(info_1.encode("hex"))
for x in range(16):
    info_2[x] = ((ord(info_1[x]) << (x & 7)) + (ord(info_1[x]) >> (8 - (x & 7)))) % 256
print(info_2)
keep_alive2 = "".join(["{:02X}".format(x) for x in info_2])
print keep_alive2.decode("hex").encode("hex")