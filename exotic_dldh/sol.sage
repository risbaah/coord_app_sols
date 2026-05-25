# Sage is very similar to python as you can see,
# You might need to pip install pycryptodome inside the docker
# to run this template GLHF :)

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Hash import SHA256

p = 0xea5d4211ffd4d1c88af967d9949c96aad3440201c9c5b60980570283563bf4b0288a027685f4b6c0e2153d6049ed323185680056c7d3723eb37703d146d3cd4b
n = 20
F = GF(p)

X = Matrix(F, 20, 20, eval(open("gen.matrix").read()))
H = Matrix(F, 20, 20, eval(open("out.matrix").read()))

J, P = X.jordan_form(transformation=True)  #transformation = true computes the P matrix too along with J
H_J = P.inverse() * H * P # Jordan form of H = J^secret


secret = 0
for i in range(19):
    if J[i, i+1] == 1 and (J[i,i] == J[i+1,i+1]):   # checking if J[i,i+1]th element is one and if, J[i,i] == J{i+1,i+1}
        lamda = J[i, i]
        lamda_s = H_J[i, i]
        next_to_lambda_s = H_J[i, i+1]

        secret = int((next_to_lambda_s*lamda)/ lamda_s) #secret can be computed as H_J[i,i]/(H_J[i,i+1] x J[i,i]
        break

K = SHA256.new(data=str(secret).encode()).digest()[:128]

import json
from os import urandom

enc = json.load(open("flag.enc", "r"))
cipher = AES.new(K, AES.MODE_CBC, bytes.fromhex(enc["iv"]))
print(unpad(cipher.decrypt(bytes.fromhex(enc["ct"])), 16).decode())
