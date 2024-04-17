from Crypto.PublicKey import RSA
from Crypto.Util.number import getPrime
from math import gcd


def generate_keypair(bits):
    p = getPrime(bits)
    q = getPrime(bits)
    n = p * q

    e = 65537
    phi = (p - 1) * (q - 1)
    if gcd(e, phi) != 1:
        return generate_keypair(bits)

    d = pow(e, -1, phi)
    return n, e, d


def export_public_key(rsa, filename):
    with open(filename, 'wb') as f:
        f.write(rsa.public_key().export_key('PEM'))


def export_private_key(rsa, filename):
    with open(filename, 'wb') as f:
        f.write(rsa.export_key('PEM'))


def main():
    n, e, d = generate_keypair(100)
    rsa = RSA.construct((n, e, d))
    export_public_key(rsa, 'public.pem')
    export_private_key(rsa, 'private.pem')


if __name__ == "__main__":
    main()
