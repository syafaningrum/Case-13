"""
client.py
---------
Dijalankan di VM Client (172.20.0.106).

Alur kerja:
  1. Untuk setiap kombinasi (skema, hash, key_size, msg_size):
     a. Buat keypair dan pre-sign 100 pesan berbeda.
     b. Untuk setiap sample:
        - Buka koneksi TCP ke server.
        - Kirim payload (pesan + signature + public key).
        - Mulai timer TEPAT SEBELUM send.
        - Hentikan timer TEPAT SETELAH menerima ACK dari server.
        - Catat transmission delay.
  2. Simpan semua hasil ke CSV.

Kenapa pre-sign sebelum transmisi?
  Supaya waktu signing tidak ikut terhitung dalam transmission delay.
  Kita mau mengukur murni waktu kirim-terima data di jaringan.

Kenapa ACK dikirim server SEBELUM verifikasi?
  Supaya waktu verifikasi di server tidak ikut terhitung dalam delay kita.

Server: 172.20.0.103:5005
"""

# ===========================================================================
# IMPORT LIBRARY
# ===========================================================================
import base64
import csv
import hashlib
import json
import os
import random
import socket
import struct
import time

# Untuk ECDSA: pakai library `cryptography`
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import (
    Encoding, PublicFormat
)
from cryptography.exceptions import InvalidSignature


# ===========================================================================
# BAGIAN 1: IMPLEMENTASI ECDSA
# ===========================================================================
# ECDSA = Elliptic Curve Digital Signature Algorithm
#
# Konsep dasar:
#   - Keamanannya bergantung pada "Elliptic Curve Discrete Logarithm Problem"
#     (sangat sulit menghitung x dari y = x*G di kurva eliptik).
#   - Keunggulan vs RSA: key lebih kecil untuk level keamanan yang sama.
#     Contoh: secp256r1 (256-bit) setara keamanan RSA-3072.
#
# Kurva yang dipakai:
#   secp192r1 : 192-bit, paling cepat, keamanan paling rendah
#   secp256r1 : 256-bit, standar industri (TLS, Bitcoin, dll)
#   secp384r1 : 384-bit, paling lambat, keamanan paling tinggi
# ===========================================================================

# Pemetaan nama kurva ke objek kurva dari library cryptography
ECDSA_CURVE_MAP = {
    "secp192r1": ec.SECP192R1(),
    "secp256r1": ec.SECP256R1(),
    "secp384r1": ec.SECP384R1(),
}

# Pemetaan nama hash ke CLASS hash (bukan instance!)
# Dipanggil dengan () saat dipakai: ECDSA_HASH_MAP["SHA-256"]() → objek SHA256
ECDSA_HASH_MAP = {
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
}


def generate_ecdsa_keypair(curve_name: str):
    """
    Membuat pasangan kunci ECDSA.

    Proses internal library:
      1. Pilih private key x secara acak (bilangan dalam range kurva)
      2. Hitung public key Q = x * G (G = titik generator kurva)
         Perkalian titik di kurva eliptik ini yang sulit dibalik.

    Args:
        curve_name : 'secp192r1', 'secp256r1', atau 'secp384r1'

    Returns:
        Tuple (private_key, public_key) — objek dari library cryptography
    """
    if curve_name not in ECDSA_CURVE_MAP:
        raise ValueError(f"Kurva tidak dikenal: {curve_name}. "
                         f"Pilih dari: {list(ECDSA_CURVE_MAP.keys())}")

    private_key = ec.generate_private_key(ECDSA_CURVE_MAP[curve_name], default_backend())
    return private_key, private_key.public_key()


def ecdsa_sign(private_key, message: bytes, hash_name: str) -> bytes:
    """
    Menandatangani pesan dengan ECDSA.

    Proses internal (dilakukan otomatis oleh library):
      1. H = hash(message)                → hash pesan jadi angka
      2. k = bilangan acak                → nonce unik per signature
      3. R = k * G                        → titik di kurva
      4. r = koordinat-x dari R mod n
      5. s = k^{-1} * (H + x*r) mod n    → x = private key
      6. Signature = encode(r, s) ke format DER

    Kenapa k harus unik setiap signing?
      Jika k sama dipakai dua kali (untuk dua pesan berbeda), attacker bisa
      menghitung private key x! Ini pernah terjadi di Sony PS3 (2010).

    Args:
        private_key : Private key ECDSA
        message     : Pesan (bytes)
        hash_name   : 'SHA-256' atau 'SHA-384'

    Returns:
        Signature dalam format DER (bytes)
    """
    if hash_name not in ECDSA_HASH_MAP:
        raise ValueError(f"Hash tidak dikenal: {hash_name}")

    return private_key.sign(message, ec.ECDSA(ECDSA_HASH_MAP[hash_name]()))


def serialize_ecdsa_public_key(public_key) -> str:
    """
    Mengubah public key ECDSA ke string base64 untuk dikirim via JSON.

    Format DER (Distinguished Encoding Rules) adalah format biner standar
    untuk kunci kriptografi. Karena JSON tidak bisa menyimpan bytes mentah,
    kita encode ke base64 dulu.

    Returns:
        String base64 dari DER bytes public key
    """
    der_bytes = public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    return base64.b64encode(der_bytes).decode("utf-8")


# ===========================================================================
# BAGIAN 2: IMPLEMENTASI ELGAMAL
# ===========================================================================
# ElGamal Digital Signature Scheme — implementasi manual from scratch.
#
# Skema matematika:
#   Keygen : pilih prime p, generator g, private x → public y = g^x mod p
#   Sign   : pilih k acak coprime (p-1)
#             r = g^k mod p
#             s = k^{-1} * (H(m) - x*r) mod (p-1)
#             Signature = (r, s)
#   Verify : g^{H(m)} ≡ y^r * r^s (mod p)
# ===========================================================================

# Prime standar yang digunakan (RFC 3526 / FIPS — nilai terstandarisasi)
PRIME_1024 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)
PRIME_2048 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)
PRIME_3072 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64"
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7"
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B"
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C"
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31"
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF", 16
)

ELGAMAL_GENERATOR = 2  # Generator standar g = 2

ELGAMAL_PRIME_MAP = {
    "1024-bit": PRIME_1024,
    "2048-bit": PRIME_2048,
    "3072-bit": PRIME_3072,
}

# Hash untuk ElGamal menggunakan hashlib (bukan library cryptography)
# karena kita perlu hasilnya sebagai integer, bukan objek
ELGAMAL_HASH_MAP = {
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
}


# --- Fungsi matematika pembantu ---

def extended_gcd(a: int, b: int):
    """
    Algoritma Extended Euclidean (versi ITERATIF, bukan rekursif).

    Kenapa iteratif?
      Untuk prime 3072-bit, rekursi bisa ribuan level dalam → RecursionError.
      Versi iteratif tidak punya batasan ini.

    Mengembalikan (g, x) sehingga: a*x ≡ g (mod b), di mana g = gcd(a, b)
    Jika g = 1, maka x = invers modular a terhadap b.
    """
    old_r, r = a, b
    old_s, s = 1, 0

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    return old_r, old_s  # (gcd, koefisien x)


def mod_inverse(a: int, m: int) -> int:
    """
    Menghitung invers modular: a^{-1} mod m

    Contoh: mod_inverse(3, 11) = 4, karena 3*4 = 12 ≡ 1 (mod 11)

    Dipakai saat signing untuk menghitung k^{-1} mod (p-1).

    Raises:
        ValueError jika gcd(a, m) != 1 (invers tidak ada)
    """
    g, x = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Invers modular tidak ada: gcd({a}, {m}) = {g}")
    return x % m


def gcd(a: int, b: int) -> int:
    """GCD klasik dengan algoritma Euclidean."""
    while b:
        a, b = b, a % b
    return a


def random_coprime(n: int) -> int:
    """
    Memilih bilangan acak k dalam [2, n-1] yang coprime dengan n.

    'coprime' artinya gcd(k, n) = 1.
    Ini diperlukan agar k^{-1} mod n ada (bisa dihitung inversnya).

    Pakai os.urandom() untuk keacakan kriptografi (lebih aman dari random.randint).
    """
    while True:
        k = int.from_bytes(os.urandom(len(bin(n)) // 8 + 1), 'big') % (n - 2) + 2
        if gcd(k, n) == 1:
            return k


def generate_elgamal_keypair(prime_name: str) -> dict:
    """
    Membuat pasangan kunci ElGamal.

    Langkah-langkah:
      1. Ambil prime p dan generator g
      2. Pilih private key x secara acak
      3. Hitung public key y = g^x mod p

    Kenapa ini lambat dibanding ECDSA?
      pow(g, x, p) dengan p 3072-bit melibatkan ratusan perkalian bilangan
      besar secara berulang. Meski Python mengoptimasi ini dengan modular
      exponentiation (square-and-multiply), tetap jauh lebih lambat dari
      operasi kurva eliptik ECDSA.

    Args:
        prime_name : '1024-bit', '2048-bit', atau '3072-bit'

    Returns:
        Dict: p, g, x (private), y (public), prime_name
    """
    if prime_name not in ELGAMAL_PRIME_MAP:
        raise ValueError(f"Prime tidak dikenal: {prime_name}.")

    p = ELGAMAL_PRIME_MAP[prime_name]
    g = ELGAMAL_GENERATOR
    x = int.from_bytes(os.urandom((p.bit_length() + 7) // 8), 'big') % (p - 3) + 2
    y = pow(g, x, p)

    return {"p": p, "g": g, "x": x, "y": y, "prime_name": prime_name}


def elgamal_sign(keypair: dict, message: bytes, hash_name: str) -> tuple:
    """
    Menandatangani pesan dengan ElGamal.

    Algoritma:
      1. H = int(hash(message))
      2. Pilih k acak coprime dengan (p-1)
      3. r = g^k mod p
      4. s = k^{-1} * (H - x*r) mod (p-1)
      5. Jika s == 0, ulang dengan k baru

    Kenapa k harus coprime dengan (p-1)?
      Karena kita butuh k^{-1} mod (p-1) untuk menghitung s.
      Invers hanya ada jika gcd(k, p-1) = 1.

    Returns:
        Tuple (r, s) sebagai signature
    """
    if hash_name not in ELGAMAL_HASH_MAP:
        raise ValueError(f"Hash tidak dikenal: {hash_name}")

    p, g, x = keypair["p"], keypair["g"], keypair["x"]
    p1 = p - 1
    H = int.from_bytes(ELGAMAL_HASH_MAP[hash_name](message).digest(), 'big')

    while True:
        k = random_coprime(p1)
        r = pow(g, k, p)
        s = (mod_inverse(k, p1) * (H - x * r)) % p1
        if s != 0:
            break

    return (r, s)


def serialize_elgamal_signature(signature: tuple) -> bytes:
    """
    Mengubah signature ElGamal (r, s) menjadi bytes.

    Format:
      [4 byte: len(r)][r bytes][4 byte: len(s)][s bytes]

    Kenapa perlu panjang eksplisit?
      r dan s adalah integer yang ukurannya bervariasi tergantung nilainya.
      Tanpa informasi panjang, penerima tidak tahu di mana r berakhir.
    """
    r, s = signature
    r_b = r.to_bytes((r.bit_length() + 7) // 8 or 1, 'big')
    s_b = s.to_bytes((s.bit_length() + 7) // 8 or 1, 'big')
    return len(r_b).to_bytes(4, 'big') + r_b + len(s_b).to_bytes(4, 'big') + s_b


def serialize_elgamal_public_key(keypair: dict) -> str:
    """
    Mengubah parameter publik ElGamal (p, g, y) ke string base64 untuk JSON.

    PENTING: Private key x TIDAK ikut dikirim!
      Server hanya butuh p, g, y untuk verifikasi.
      Mengirim x ke server adalah kebocoran keamanan yang serius.

    p, g, y dikirim sebagai hex string karena:
      - JSON tidak mendukung integer sebesar ini (3072-bit = ~925 digit desimal)
      - hex lebih compact dan mudah di-parse
    """
    kp_public = {
        "p"         : hex(keypair["p"]),
        "g"         : hex(keypair["g"]),
        "y"         : hex(keypair["y"]),  # HANYA public key y
        "prime_name": keypair["prime_name"],
    }
    return base64.b64encode(json.dumps(kp_public).encode("utf-8")).decode("utf-8")


# ===========================================================================
# BAGIAN 3: UTILITAS SOCKET / FRAMING
# ===========================================================================
# TCP adalah stream protocol — tidak ada batas antar pesan.
# Kita pakai "length-prefixed framing" untuk memisahkan payload:
#   Kirim : [4 byte panjang][data]
#   Terima: baca 4 byte dulu → tahu panjang → baca sejumlah itu
# ===========================================================================

ACK_MESSAGE = b"ACK"  # 3 bytes yang dikirim server sebagai konfirmasi
TIMEOUT_SEC = 10      # Timeout socket per operasi (detik)


def send_payload(conn: socket.socket, payload_dict: dict):
    """
    Mengirim payload JSON dengan format length-prefixed.

    Format: [4 byte big-endian panjang][JSON bytes]

    conn.sendall() lebih aman dari conn.send() karena memastikan semua
    bytes terkirim (send() bisa mengembalikan jumlah < yang diminta).
    """
    payload_bytes = json.dumps(payload_dict).encode("utf-8")
    header = struct.pack("!I", len(payload_bytes))  # "!I" = big-endian uint32
    conn.sendall(header + payload_bytes)


def recv_ack(conn: socket.socket) -> bytes:
    """
    Menerima ACK dari server dengan loop untuk menangani fragmentasi TCP.

    ACK cuma 3 bytes, tapi secara teknikal TCP tidak menjamin 1 send = 1 recv.
    Loop ini menangani kasus di mana ACK datang terpecah (sangat jarang
    di jaringan lokal, tapi benar secara protokol).
    """
    data = b""
    while len(data) < len(ACK_MESSAGE):
        chunk = conn.recv(len(ACK_MESSAGE) - len(data))
        if not chunk:
            raise ConnectionError("Koneksi ditutup server sebelum ACK diterima")
        data += chunk
    return data


def generate_random_message(size: int) -> bytes:
    """Membuat pesan acak sejumlah `size` bytes."""
    return random.randbytes(size)


# ===========================================================================
# BAGIAN 4: FUNGSI TRANSMISI SATU SAMPLE
# ===========================================================================

def transmit_one_sample(scheme: str, key_size: str, hash_name: str,
                        msg_size: int, sample_idx: int,
                        message: bytes, sig_b64: str, pubkey_b64: str) -> float:
    """
    Mengirim satu sample ke server dan mengukur transmission delay.

    Setiap sample membuka koneksi TCP baru (bukan connection reuse).
    Kenapa? Karena ini lebih realistis untuk skenario real-world di mana
    setiap permintaan bisa datang dari client yang berbeda.

    Pengukuran:
      t_start = tepat SEBELUM conn.sendall() → payload mulai dikirim
      t_end   = tepat SETELAH recv_ack()     → ACK sudah diterima
      delay   = t_end - t_start              → round-trip transmission time

    Returns:
        Transmission delay dalam milidetik
    """
    payload = {
        "scheme"      : scheme,
        "key_size"    : key_size,
        "hash_name"   : hash_name,
        "msg_size"    : msg_size,
        "sample_idx"  : sample_idx,
        "message_b64" : base64.b64encode(message).decode("utf-8"),
        "sig_b64"     : sig_b64,
        "pubkey_b64"  : pubkey_b64,
    }

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as conn:
        conn.settimeout(TIMEOUT_SEC)
        # TCP_NODELAY: nonaktifkan Nagle's algorithm agar data langsung dikirim
        # tanpa menunggu buffer penuh. Ini penting untuk mengukur latensi murni.
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn.connect((SERVER_IP, SERVER_PORT))

        # === MULAI TIMER — payload belum dikirim ===
        t_start = time.perf_counter()
        send_payload(conn, payload)
        ack = recv_ack(conn)
        # === HENTIKAN TIMER — ACK sudah diterima ===
        t_end = time.perf_counter()

    if ack != ACK_MESSAGE:
        raise ValueError(f"ACK tidak valid: {ack!r}")

    return (t_end - t_start) * 1000  # konversi detik → milidetik


# ===========================================================================
# BAGIAN 5: FUNGSI BENCHMARK PER SKEMA
# ===========================================================================

def benchmark_transmission_ecdsa(curve_name: str, hash_name: str,
                                  msg_size: int, num_samples: int,
                                  csv_writer, csv_file):
    """
    Mengukur transmission delay ECDSA untuk satu konfigurasi.

    Alur:
      1. Generate keypair (satu kali)
      2. Pre-sign 100 pesan (di luar pengukuran — kita tidak ukur ini)
      3. Kirim satu per satu ke server dan ukur delay tiap sample
      4. Tulis tiap baris ke CSV segera (tidak tunggu semua selesai)
    """
    print(f"  Generating ECDSA keypair ({curve_name})...", end=" ", flush=True)
    private_key, public_key = generate_ecdsa_keypair(curve_name)
    pubkey_b64 = serialize_ecdsa_public_key(public_key)
    print("done.")

    # Pre-sign: buat semua signature sebelum mulai transmisi
    # Ini memastikan waktu signing tidak masuk ke pengukuran delay
    print(f"  Pre-signing {num_samples} pesan...", end=" ", flush=True)
    pre_signed = []
    for _ in range(num_samples):
        msg = generate_random_message(msg_size)
        sig = ecdsa_sign(private_key, msg, hash_name)
        pre_signed.append((msg, base64.b64encode(sig).decode("utf-8")))
    print("done.")

    delays = []
    errors = 0

    for i, (message, sig_b64) in enumerate(pre_signed):
        try:
            delay_ms = transmit_one_sample(
                "ECDSA", curve_name, hash_name, msg_size, i,
                message, sig_b64, pubkey_b64
            )
            delays.append(delay_ms)

            # Tulis langsung ke CSV supaya data tidak hilang jika error di tengah
            csv_writer.writerow({
                "scheme"         : "ECDSA",
                "key_size"       : curve_name,
                "hash_name"      : hash_name,
                "msg_size_bytes" : msg_size,
                "sample_idx"     : i,
                "delay_ms"       : round(delay_ms, 6),
            })

            if (i + 1) % 10 == 0:
                avg_so_far = sum(delays) / len(delays)
                print(f"    [{i+1}/{num_samples}] avg={avg_so_far:.3f}ms", flush=True)

        except Exception as e:
            errors += 1
            print(f"    ERROR sample {i}: {e}")

    csv_file.flush()
    avg = sum(delays) / len(delays) if delays else 0
    print(f"  → Avg delay: {avg:.3f}ms "
          f"({len(delays)}/{num_samples} berhasil"
          + (f", {errors} gagal" if errors else "") + ")")
    return avg


def benchmark_transmission_elgamal(prime_name: str, hash_name: str,
                                    msg_size: int, num_samples: int,
                                    keypair: dict, csv_writer, csv_file):
    """
    Mengukur transmission delay ElGamal untuk satu konfigurasi.

    Keypair diterima sebagai parameter karena sudah di-generate di luar
    (ElGamal keygen mahal — lebih efisien generate sekali per prime).
    """
    pubkey_b64 = serialize_elgamal_public_key(keypair)

    print(f"  Pre-signing {num_samples} pesan...", end=" ", flush=True)
    pre_signed = []
    for _ in range(num_samples):
        msg = generate_random_message(msg_size)
        sig_tuple = elgamal_sign(keypair, msg, hash_name)
        sig_bytes = serialize_elgamal_signature(sig_tuple)
        pre_signed.append((msg, base64.b64encode(sig_bytes).decode("utf-8")))
    print("done.")

    delays = []
    errors = 0

    for i, (message, sig_b64) in enumerate(pre_signed):
        try:
            delay_ms = transmit_one_sample(
                "ElGamal", prime_name, hash_name, msg_size, i,
                message, sig_b64, pubkey_b64
            )
            delays.append(delay_ms)

            csv_writer.writerow({
                "scheme"         : "ElGamal",
                "key_size"       : prime_name,
                "hash_name"      : hash_name,
                "msg_size_bytes" : msg_size,
                "sample_idx"     : i,
                "delay_ms"       : round(delay_ms, 6),
            })

            if (i + 1) % 10 == 0:
                avg_so_far = sum(delays) / len(delays)
                print(f"    [{i+1}/{num_samples}] avg={avg_so_far:.3f}ms", flush=True)

        except Exception as e:
            errors += 1
            print(f"    ERROR sample {i}: {e}")

    csv_file.flush()
    avg = sum(delays) / len(delays) if delays else 0
    print(f"  → Avg delay: {avg:.3f}ms "
          f"({len(delays)}/{num_samples} berhasil"
          + (f", {errors} gagal" if errors else "") + ")")
    return avg


# ===========================================================================
# BAGIAN 6: KONFIGURASI & MAIN
# ===========================================================================

SERVER_IP    = "172.20.0.103"
SERVER_PORT  = 5005
NUM_SAMPLES  = 100
MESSAGE_SIZES  = [50, 100, 150, 200, 250]
HASH_NAMES     = ["SHA-256", "SHA-384"]
ECDSA_CURVES   = ["secp192r1", "secp256r1", "secp384r1"]
ELGAMAL_PRIMES = ["1024-bit", "2048-bit", "3072-bit"]
OUTPUT_DIR   = "results"
OUTPUT_FILE  = os.path.join(OUTPUT_DIR, "transmission_delay.csv")


def run_client():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    fieldnames = [
        "scheme", "key_size", "hash_name",
        "msg_size_bytes", "sample_idx", "delay_ms"
    ]

    total_configs = (
        len(ECDSA_CURVES)   * len(HASH_NAMES) * len(MESSAGE_SIZES) +
        len(ELGAMAL_PRIMES) * len(HASH_NAMES) * len(MESSAGE_SIZES)
    )
    current = 0

    print(f"{'='*60}")
    print(f"CLIENT Digital Signature Benchmark")
    print(f"Server: {SERVER_IP}:{SERVER_PORT}")
    print(f"Output: {OUTPUT_FILE}")
    print(f"Samples per kombinasi: {NUM_SAMPLES}")
    print(f"Total konfigurasi: {total_configs}")
    print(f"{'='*60}\n")

    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()

        # ---- ECDSA ----
        print("[ ECDSA Transmission Benchmark ]\n")
        for curve_name in ECDSA_CURVES:
            for hash_name in HASH_NAMES:
                for msg_size in MESSAGE_SIZES:
                    current += 1
                    print(f"[{current}/{total_configs}] "
                          f"ECDSA/{curve_name}/{hash_name}/msg={msg_size}B")
                    benchmark_transmission_ecdsa(
                        curve_name, hash_name, msg_size, NUM_SAMPLES,
                        writer, csv_file
                    )
                    print()

        # ---- ElGamal ----
        print("\n[ ElGamal Transmission Benchmark ]\n")

        # Pre-generate semua keypair ElGamal di awal.
        # Ini sengaja dilakukan sekali sebelum loop benchmark karena:
        #   1. Keygen ElGamal sangat lambat (terutama 3072-bit)
        #   2. Kita tidak mau waktu keygen tercampur dengan waktu transmisi
        print("Pre-generating ElGamal keypairs (butuh waktu)...")
        elgamal_keypairs = {}
        for prime_name in ELGAMAL_PRIMES:
            print(f"  {prime_name}...", end=" ", flush=True)
            elgamal_keypairs[prime_name] = generate_elgamal_keypair(prime_name)
            print("done.")
        print()

        for prime_name in ELGAMAL_PRIMES:
            for hash_name in HASH_NAMES:
                for msg_size in MESSAGE_SIZES:
                    current += 1
                    print(f"[{current}/{total_configs}] "
                          f"ElGamal/{prime_name}/{hash_name}/msg={msg_size}B")
                    benchmark_transmission_elgamal(
                        prime_name, hash_name, msg_size, NUM_SAMPLES,
                        elgamal_keypairs[prime_name],
                        writer, csv_file
                    )
                    print()

    print(f"\n{'='*60}")
    print(f"Selesai! Hasil disimpan ke: {OUTPUT_FILE}")
    print(f"{'='*60}")


if __name__ == "__main__":
    run_client()
