#!/usr/bin/env python3
"""Signs an APK with APK Signature Scheme v2 (enough for Android 7+).

The build on GitHub produces an unsigned APK; the key stays with the
maintainer. Usage:

    sign.py genkey KEY.pem            new RSA key + self-signed certificate
    sign.py sign KEY.pem IN.apk OUT.apk

KEY.pem holds the private key and the certificate. Keep it: Android installs
an update only if it is signed with the same key.
"""
import datetime
import hashlib
import struct
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

SIG_RSA_PKCS1_SHA256 = 0x0103
V2_ID = 0x7109871A
MAGIC = b"APK Sig Block 42"
CHUNK = 1 << 20


def lp(b):  # uint32 length-prefixed
    return struct.pack("<I", len(b)) + b


def genkey(path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Lazeyka"), x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Lazeyka")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=365 * 40)).sign(key, hashes.SHA256()))
    with open(path, "wb") as f:
        f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    print("key written:", path)
    print("certificate SHA-256:", hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest())


def load(path):
    data = open(path, "rb").read()
    key = serialization.load_pem_private_key(data, password=None)
    cert = x509.load_pem_x509_certificate(data[data.index(b"-----BEGIN CERTIFICATE-----"):])
    return key, cert


def find_eocd(apk):
    for i in range(len(apk) - 22, max(-1, len(apk) - 22 - 65536) - 1, -1):
        if apk[i:i + 4] == b"PK\x05\x06":
            clen = struct.unpack_from("<H", apk, i + 20)[0]
            if i + 22 + clen == len(apk):
                return i
    raise SystemExit("not a zip: no end of central directory")


def chunk_digest(parts):
    digests = []
    for part in parts:
        for off in range(0, len(part), CHUNK):
            c = part[off:off + CHUNK]
            digests.append(hashlib.sha256(b"\xa5" + struct.pack("<I", len(c)) + c).digest())
    return hashlib.sha256(b"\x5a" + struct.pack("<I", len(digests)) + b"".join(digests)).digest()


def sign(keypath, src, dst):
    key, cert = load(keypath)
    apk = open(src, "rb").read()
    eocd = find_eocd(apk)
    cd_size, cd_off = struct.unpack_from("<II", apk, eocd + 12)
    if cd_off + cd_size != eocd:
        raise SystemExit("unexpected layout (zip64 or data between central directory and its end)")
    if apk[cd_off - 16:cd_off] == MAGIC:
        raise SystemExit("already signed")
    entries, cd, end = apk[:cd_off], apk[cd_off:eocd], bytearray(apk[eocd:])
    # the digest is over the end record with the central directory offset as
    # it will be seen: pointing at where the signing block starts
    digest = chunk_digest([entries, cd, bytes(end)])

    cert_der = cert.public_bytes(serialization.Encoding.DER)
    pub_der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    digests = lp(struct.pack("<I", SIG_RSA_PKCS1_SHA256) + lp(digest))
    signed_data = lp(digests) + lp(lp(cert_der)) + lp(b"")
    sig = key.sign(signed_data, padding.PKCS1v15(), hashes.SHA256())
    signer = lp(signed_data) + lp(lp(struct.pack("<I", SIG_RSA_PKCS1_SHA256) + lp(sig))) + lp(pub_der)
    value = lp(lp(signer))

    pair = struct.pack("<Q", 4 + len(value)) + struct.pack("<I", V2_ID) + value
    size = len(pair) + 8 + 16  # pairs + trailing size + magic
    block = struct.pack("<Q", size) + pair + struct.pack("<Q", size) + MAGIC
    struct.pack_into("<I", end, 16, cd_off + len(block))
    with open(dst, "wb") as f:
        f.write(entries + block + cd + bytes(end))
    print("signed:", dst)
    print("certificate SHA-256:", hashlib.sha256(cert_der).hexdigest())


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "genkey":
        genkey(sys.argv[2])
    elif len(sys.argv) == 5 and sys.argv[1] == "sign":
        sign(*sys.argv[2:])
    else:
        print(__doc__)
        sys.exit(2)
