# SHA-256 Implementation from Scratch
import numpy as np

# Get plaintext input from user
plain_text = input("Please enter a plaintext of less than 64 characters:")
while len(plain_text) > 64:
    plain_text = input("Message too long. Please enter a plaintext of less than 64 characters:")

# Convert ASCII text to binary and pad the message
def ascii_to_binary(text):
    binary_text = ''.join(format(ord(char), '08b') for char in text)
    binary_text += '1'
    while len(binary_text) % 512 != 448:
        binary_text += '0'
    binary_length = format(len(text) * 8, '064b')
    binary_text += binary_length
    return binary_text

binary_text = ascii_to_binary(plain_text)

# Parse 512-bit block into 16 32-bit words
def parsing(binary_text):
    return [int(binary_text[i:i+32], 2) for i in range(0, len(binary_text), 32)]

W = parsing(binary_text)

# Extend to 64 words
def right_rotate(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def sigma0(x):
    return right_rotate(x, 7) ^ right_rotate(x, 18) ^ (x >> 3)

def sigma1(x):
    return right_rotate(x, 17) ^ right_rotate(x, 19) ^ (x >> 10)

for t in range(16, 64):
    W.append((sigma1(W[t - 2]) + W[t - 7] + sigma0(W[t - 15]) + W[t - 16]) & 0xFFFFFFFF)

# Initial hash values (first 32 bits of the fractional parts of square roots of first 8 primes)
H = [
    0x6a09e667,
    0xbb67ae85,
    0x3c6ef372,
    0xa54ff53a,
    0x510e527f,
    0x9b05688c,
    0x1f83d9ab,
    0x5be0cd19
]

# SHA-256 constants (first 32 bits of the fractional parts of cube roots of first 64 primes)
K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

def capsigma0(x):
    return right_rotate(x, 2) ^ right_rotate(x, 13) ^ right_rotate(x, 22)

def capsigma1(x):
    return right_rotate(x, 6) ^ right_rotate(x, 11) ^ right_rotate(x, 25)

a, b, c, d, e, f, g, h = H

for i in range(64):
    T1 = (h + capsigma1(e) + ch(e, f, g) + K[i] + W[i]) & 0xFFFFFFFF
    T2 = (capsigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
    h = g
    g = f
    f = e
    e = (d + T1) & 0xFFFFFFFF
    d = c
    c = b
    b = a
    a = (T1 + T2) & 0xFFFFFFFF

H[0] = (H[0] + a) & 0xFFFFFFFF
H[1] = (H[1] + b) & 0xFFFFFFFF
H[2] = (H[2] + c) & 0xFFFFFFFF
H[3] = (H[3] + d) & 0xFFFFFFFF
H[4] = (H[4] + e) & 0xFFFFFFFF
H[5] = (H[5] + f) & 0xFFFFFFFF
H[6] = (H[6] + g) & 0xFFFFFFFF
H[7] = (H[7] + h) & 0xFFFFFFFF

ciphertext = ''.join([format(hv, '08x') for hv in H])
print("SHA-256 hash:", ciphertext)

# To compare with hashlib:
import hashlib
print("Expected:    ", hashlib.sha256(plain_text.encode()).hexdigest())

