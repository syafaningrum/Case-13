"""
benchmark_computation.py
------------------------
Script benchmarking KOMPUTASI (sign + verify) untuk semua kombinasi:
  - Skema : ECDSA, ElGamal
  - Hash  : SHA-256, SHA-384
  - Key   : 3 ukuran per skema
  - Pesan : 50, 100, 150, 200, 250 bytes

Semua implementasi kriptografi (ECDSA & ElGamal) ada langsung di file ini
supaya tidak perlu file terpisah.

Output: results/computational_delay.csv

Penulis : Project-2 Case-13 Team
Tanggal : 2025
"""

# ===========================================================================
# IMPORT LIBRARY
# ===========================================================================
import csv
import hashlib
import os
import random
import statistics
import time

# Untuk ECDSA: kita pakai library `cryptography` (sudah terinstall di Python)
# Library ini menyediakan implementasi ECDSA yang sudah dioptimasi dan aman.
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


# ===========================================================================
# BAGIAN 1: IMPLEMENTASI ECDSA
# ===========================================================================
# ECDSA = Elliptic Curve Digital Signature Algorithm
#
# Cara kerjanya secara singkat:
#   - Keamanannya bergantung pada sulitnya memecahkan "discrete logarithm"
#     di kurva eliptik.
#   - Makin besar kurva (bit-nya), makin aman, tapi makin lambat.
#   - Signature ECDSA jauh lebih kecil daripada RSA untuk level keamanan
#     yang setara. Contoh: secp256r1 (256-bit) ≈ RSA 3072-bit.
# ===========================================================================

# --- Pemetaan nama kurva ke objek kurva dari library `cryptography` ---
# secp192r1 : 192-bit, keamanan paling rendah dari ketiganya, paling cepat
# secp256r1 : 256-bit, standar industri saat ini (dipakai di TLS, Bitcoin, dll)
# secp384r1 : 384-bit, keamanan ekstra tinggi (NSA Suite B), paling lambat
ECDSA_CURVE_MAP = {
    "secp192r1": ec.SECP192R1(),
    "secp256r1": ec.SECP256R1(),
    "secp384r1": ec.SECP384R1(),
}

# --- Pemetaan nama hash ke CLASS hash dari library `cryptography` ---
# Perhatikan: ini CLASS (belum di-instansiasi), bukan objek.
# Nanti dipanggil dengan () saat dipakai, contoh: ECDSA_HASH_MAP["SHA-256"]()
ECDSA_HASH_MAP = {
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
}


def generate_ecdsa_keypair(curve_name: str):
    """
    Membuat pasangan kunci ECDSA (private key + public key).

    Cara kerja:
      1. Pilih kurva eliptik berdasarkan nama.
      2. Generate private key secara random di dalam kurva tersebut.
      3. Public key diturunkan otomatis dari private key oleh library.

    Args:
        curve_name : Nama kurva ('secp192r1', 'secp256r1', 'secp384r1')

    Returns:
        Tuple (private_key, public_key) — objek dari library cryptography
    """
    if curve_name not in ECDSA_CURVE_MAP:
        raise ValueError(f"Kurva tidak dikenal: {curve_name}. "
                         f"Pilih dari: {list(ECDSA_CURVE_MAP.keys())}")

    curve = ECDSA_CURVE_MAP[curve_name]

    # generate_private_key() akan:
    #   - Memilih bilangan acak sebagai private key
    #   - Menghitung titik publik di kurva eliptik (ini jadi public key)
    private_key = ec.generate_private_key(curve, default_backend())
    public_key = private_key.public_key()

    return private_key, public_key


def ecdsa_sign(private_key, message: bytes, hash_name: str) -> bytes:
    """
    Menandatangani pesan dengan ECDSA.

    Proses internal (dilakukan otomatis oleh library):
      1. Pesan di-hash dulu: H = hash(message)
      2. Dipilih bilangan acak k
      3. Dihitung titik R = k * G (G = titik generator kurva)
      4. r = koordinat-x dari R (mod n)
      5. s = k^{-1} * (H + x*r) mod n   (x = private key)
      6. Signature = (r, s) dikemas dalam format DER

    Args:
        private_key : Private key ECDSA
        message     : Pesan yang akan ditandatangani (bytes)
        hash_name   : 'SHA-256' atau 'SHA-384'

    Returns:
        Signature dalam format DER (bytes) — siap dikirim/disimpan
    """
    if hash_name not in ECDSA_HASH_MAP:
        raise ValueError(f"Hash tidak dikenal: {hash_name}")

    # Library melakukan hashing + signing secara internal dalam satu panggilan.
    # ec.ECDSA(hash_algo) memberitahu library hash apa yang dipakai.
    signature = private_key.sign(
        message,
        ec.ECDSA(ECDSA_HASH_MAP[hash_name]())
    )
    return signature


def ecdsa_verify(public_key, message: bytes, signature: bytes,
                 hash_name: str) -> bool:
    """
    Memverifikasi tanda tangan ECDSA.

    Proses verifikasi (dilakukan oleh library):
      1. Pesan di-hash: H = hash(message)
      2. Signature (r, s) di-decode dari format DER
      3. Dihitung: w = s^{-1} mod n
      4. Dihitung: u1 = H*w mod n, u2 = r*w mod n
      5. Titik X = u1*G + u2*Q  (Q = public key)
      6. Signature valid jika koordinat-x dari X == r

    Args:
        public_key  : Public key ECDSA
        message     : Pesan asli (bytes) — harus sama persis saat signing
        signature   : Signature DER (bytes)
        hash_name   : Hash yang dipakai saat signing

    Returns:
        True jika valid, False jika tidak valid
    """
    if hash_name not in ECDSA_HASH_MAP:
        raise ValueError(f"Hash tidak dikenal: {hash_name}")

    try:
        # Jika signature tidak valid, library akan raise InvalidSignature
        public_key.verify(
            signature,
            message,
            ec.ECDSA(ECDSA_HASH_MAP[hash_name]())
        )
        return True
    except InvalidSignature:
        return False


# ===========================================================================
# BAGIAN 2: IMPLEMENTASI ELGAMAL
# ===========================================================================
# ElGamal Digital Signature Scheme (implementasi manual/from scratch)
#
# Cara kerjanya:
#   Keygen : pilih prime p dan generator g,
#             private key x (acak), public key y = g^x mod p
#   Sign   : pilih k acak coprime dengan (p-1)
#             r = g^k mod p
#             s = k^{-1} * (H(m) - x*r) mod (p-1)
#             Signature = (r, s)
#   Verify : g^{H(m)} ≡ y^r * r^s (mod p)
#
# Kenapa perlu prime besar?
#   Keamanan ElGamal bergantung pada sulitnya "discrete logarithm mod p".
#   Makin besar p, makin aman tapi makin lambat (operasi mod p besar = berat).
#
# Catatan: Implementasi ini untuk TUJUAN AKADEMIS.
#          Produksi sebaiknya pakai library terverifikasi (misal: PyCryptodome).
# ===========================================================================

# --- Prime 1024-bit (MODP Group 2, RFC 2409) ---
# Cepat tapi tidak direkomendasikan untuk keamanan modern.
PRIME_1024 = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381"
    "FFFFFFFFFFFFFFFF", 16
)

# --- Prime 2048-bit (MODP Group 14, RFC 3526) ---
# Standar modern, keseimbangan antara keamanan dan performa.
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

# --- Prime 3072-bit (MODP Group 15, RFC 3526) ---
# Keamanan tinggi, paling lambat di antara ketiganya.
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

# Generator standar = 2 (nilai kecil tapi aman dengan prime di atas)
ELGAMAL_GENERATOR = 2

# Kumpulkan prime ke dalam dict supaya mudah diakses dengan nama
ELGAMAL_PRIME_MAP = {
    "1024-bit": PRIME_1024,
    "2048-bit": PRIME_2048,
    "3072-bit": PRIME_3072,
}

# Pemetaan nama hash ke fungsi hashlib untuk ElGamal
# (ElGamal manual tidak pakai library cryptography, jadi pakai hashlib langsung)
ELGAMAL_HASH_MAP = {
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
}


# --- Fungsi matematika untuk ElGamal ---

def extended_gcd(a: int, b: int):
    """
    Algoritma Extended Euclidean — versi ITERATIF.

    Kenapa iteratif, bukan rekursif?
      Versi rekursif akan menyebabkan RecursionError untuk bilangan besar
      (2048-bit / 3072-bit) karena kedalaman rekursi bisa ribuan level,
      melewati batas default Python (~1000).

    Mengembalikan (g, x, y) sehingga: a*x + b*y = g = gcd(a, b)

    Berguna untuk menghitung invers modular: jika gcd(a, m) = 1,
    maka a^{-1} mod m = x (dari hasil fungsi ini).
    """
    old_r, r = a, b
    old_s, s = 1, 0

    while r != 0:
        quotient = old_r // r
        old_r, r = r, old_r - quotient * r
        old_s, s = s, old_s - quotient * s

    # old_r = gcd, old_s = koefisien x (yang kita butuhkan untuk invers modular)
    return old_r, old_s


def mod_inverse(a: int, m: int) -> int:
    """
    Menghitung invers modular: a^{-1} mod m

    Contoh: mod_inverse(3, 7) = 5, karena 3*5 = 15 ≡ 1 (mod 7)

    Dipakai di ElGamal signing untuk menghitung k^{-1} mod (p-1).

    Raises:
        ValueError jika invers tidak ada (artinya gcd(a, m) != 1)
    """
    g, x = extended_gcd(a % m, m)
    if g != 1:
        raise ValueError(f"Invers modular tidak ada: gcd({a}, {m}) = {g}")
    return x % m


def gcd(a: int, b: int) -> int:
    """GCD (Greatest Common Divisor) dengan algoritma Euclidean biasa."""
    while b:
        a, b = b, a % b
    return a


def random_coprime(n: int) -> int:
    """
    Memilih bilangan acak k dalam [2, n-1] yang coprime dengan n (gcd(k,n)=1).

    Dipakai untuk memilih k acak saat signing ElGamal.
    k HARUS coprime dengan (p-1) agar k^{-1} mod (p-1) ada.

    Pakai os.urandom() untuk keacakan kriptografi yang lebih baik
    dibanding random.randint() biasa.
    """
    while True:
        k = int.from_bytes(os.urandom(len(bin(n)) // 8 + 1), 'big') % (n - 2) + 2
        if gcd(k, n) == 1:
            return k


def generate_elgamal_keypair(prime_name: str) -> dict:
    """
    Membuat pasangan kunci ElGamal.

    Langkah-langkah:
      1. Ambil prime p dan generator g dari ELGAMAL_PRIME_MAP
      2. Pilih private key x secara acak dalam [2, p-2]
      3. Hitung public key y = g^x mod p

    Kenapa y = g^x mod p disebut public key?
      Karena dari y, sangat sulit menghitung balik x (discrete log problem).
      Itulah yang membuat ElGamal aman.

    Args:
        prime_name : '1024-bit', '2048-bit', atau '3072-bit'

    Returns:
        Dict berisi: p (prime), g (generator), x (private), y (public),
                     prime_name (nama ukuran)
    """
    if prime_name not in ELGAMAL_PRIME_MAP:
        raise ValueError(f"Prime tidak dikenal: {prime_name}. "
                         f"Pilih dari: {list(ELGAMAL_PRIME_MAP.keys())}")

    p = ELGAMAL_PRIME_MAP[prime_name]
    g = ELGAMAL_GENERATOR

    # Private key x: bilangan acak di antara 2 dan p-2
    key_bytes = (p.bit_length() + 7) // 8
    x = int.from_bytes(os.urandom(key_bytes), 'big') % (p - 3) + 2

    # Public key y = g^x mod p (pow() Python sudah dioptimasi untuk ini)
    y = pow(g, x, p)

    return {"p": p, "g": g, "x": x, "y": y, "prime_name": prime_name}


def elgamal_sign(keypair: dict, message: bytes, hash_name: str) -> tuple:
    """
    Menandatangani pesan dengan ElGamal signature scheme.

    Algoritma signing:
      1. Hitung H = int(hash(message))  — ubah hash ke bilangan bulat
      2. Pilih k acak, coprime dengan (p-1)
      3. r = g^k mod p
      4. s = k^{-1} * (H - x*r) mod (p-1)
      5. Jika s = 0, ulangi dengan k baru (ini menghindari signature tidak valid)

    Kenapa k harus dirahasiakan dan unik tiap signing?
      Jika k bocor atau dipakai ulang, private key x bisa dihitung!
      (Ini pernah terjadi pada Sony PS3 yang memakai k tetap.)

    Args:
        keypair   : Dict hasil generate_elgamal_keypair
        message   : Pesan (bytes)
        hash_name : 'SHA-256' atau 'SHA-384'

    Returns:
        Tuple (r, s) sebagai signature
    """
    if hash_name not in ELGAMAL_HASH_MAP:
        raise ValueError(f"Hash tidak dikenal: {hash_name}")

    p = keypair["p"]
    g = keypair["g"]
    x = keypair["x"]   # private key
    p_minus_1 = p - 1  # dipakai berulang, simpan ke variabel

    # Hash pesan dan konversi ke integer
    h_bytes = ELGAMAL_HASH_MAP[hash_name](message).digest()
    H = int.from_bytes(h_bytes, 'big')

    # Loop sampai s != 0 (biasanya hanya 1 iterasi)
    while True:
        k = random_coprime(p_minus_1)
        r = pow(g, k, p)

        # k^{-1} mod (p-1), lalu hitung s
        k_inv = mod_inverse(k, p_minus_1)
        s = (k_inv * (H - x * r)) % p_minus_1

        if s != 0:
            break

    return (r, s)


def elgamal_verify(keypair: dict, message: bytes, signature: tuple,
                   hash_name: str) -> bool:
    """
    Memverifikasi tanda tangan ElGamal.

    Rumus verifikasi:
      g^{H(m)} ≡ y^r * r^s (mod p)

    Kenapa rumus ini bekerja?
      Dari signing: s = k^{-1}*(H - x*r) mod (p-1)
      → k*s ≡ H - x*r (mod p-1)
      → H ≡ x*r + k*s (mod p-1)
      Maka: g^H = g^{x*r + k*s} = (g^x)^r * (g^k)^s = y^r * r^s (mod p)

    Args:
        keypair   : Dict dengan keys p, g, y (x/private key TIDAK diperlukan)
        message   : Pesan asli (bytes)
        signature : Tuple (r, s)
        hash_name : Hash yang dipakai saat signing

    Returns:
        True jika valid, False jika tidak
    """
    if hash_name not in ELGAMAL_HASH_MAP:
        raise ValueError(f"Hash tidak dikenal: {hash_name}")

    p = keypair["p"]
    g = keypair["g"]
    y = keypair["y"]   # public key saja
    r, s = signature

    # Validasi range: r dan s harus dalam batas yang valid
    if not (0 < r < p):
        return False
    if not (0 < s < p - 1):
        return False

    # Hash pesan → integer
    h_bytes = ELGAMAL_HASH_MAP[hash_name](message).digest()
    H = int.from_bytes(h_bytes, 'big')

    # Cek persamaan: g^H mod p == (y^r * r^s) mod p
    lhs = pow(g, H, p)
    rhs = (pow(y, r, p) * pow(r, s, p)) % p

    return lhs == rhs


def serialize_elgamal_signature(signature: tuple) -> bytes:
    """
    Mengubah signature (r, s) menjadi bytes untuk disimpan/dikirim.

    Format biner:
      [4 byte: panjang r][r dalam bytes][4 byte: panjang s][s dalam bytes]

    Kenapa perlu serialisasi?
      Bilangan integer Python tidak punya ukuran tetap. Kita perlu format
      eksplisit agar penerima tahu di mana r berakhir dan s dimulai.
    """
    r, s = signature
    r_bytes = r.to_bytes((r.bit_length() + 7) // 8 or 1, 'big')
    s_bytes = s.to_bytes((s.bit_length() + 7) // 8 or 1, 'big')

    return (len(r_bytes).to_bytes(4, 'big') + r_bytes +
            len(s_bytes).to_bytes(4, 'big') + s_bytes)


def deserialize_elgamal_signature(data: bytes) -> tuple:
    """
    Mengubah bytes kembali menjadi signature (r, s).

    Kebalikan dari serialize_elgamal_signature().
    """
    r_len = int.from_bytes(data[0:4], 'big')
    r = int.from_bytes(data[4:4 + r_len], 'big')

    offset = 4 + r_len
    s_len = int.from_bytes(data[offset:offset + 4], 'big')
    s = int.from_bytes(data[offset + 4:offset + 4 + s_len], 'big')

    return (r, s)


# ===========================================================================
# BAGIAN 3: KONFIGURASI BENCHMARK
# ===========================================================================

NUM_SAMPLES    = 100
MESSAGE_SIZES  = [50, 100, 150, 200, 250]
HASH_NAMES     = ["SHA-256", "SHA-384"]
ECDSA_CURVES   = ["secp192r1", "secp256r1", "secp384r1"]
ELGAMAL_PRIMES = ["1024-bit", "2048-bit", "3072-bit"]
OUTPUT_DIR     = "results"
OUTPUT_FILE    = os.path.join(OUTPUT_DIR, "computational_delay.csv")


def generate_random_message(size: int) -> bytes:
    """Membuat pesan acak sejumlah `size` bytes."""
    return random.randbytes(size)


# ===========================================================================
# BAGIAN 4: FUNGSI BENCHMARK
# ===========================================================================

def benchmark_ecdsa(curve_name: str, hash_name: str, msg_size: int,
                    num_samples: int) -> dict:
    """
    Mengukur rata-rata waktu sign + verify ECDSA untuk konfigurasi tertentu.

    Keypair dibuat SEKALI per konfigurasi (bukan per sample) karena dalam
    skenario nyata, keypair tidak diganti-ganti tiap pesan.

    Returns:
        Dict berisi statistik: avg_sign_ms, avg_verify_ms, avg_total_ms,
        std_sign_ms, std_verify_ms, sig_size_bytes, num_samples
    """
    private_key, public_key = generate_ecdsa_keypair(curve_name)

    sign_times   = []
    verify_times = []
    sig_sizes    = []

    for i in range(num_samples):
        message = generate_random_message(msg_size)

        # --- Ukur waktu signing ---
        t0 = time.perf_counter()
        signature = ecdsa_sign(private_key, message, hash_name)
        sign_times.append((time.perf_counter() - t0) * 1000)  # konversi ke ms

        # --- Ukur waktu verifikasi ---
        t0 = time.perf_counter()
        valid = ecdsa_verify(public_key, message, signature, hash_name)
        verify_times.append((time.perf_counter() - t0) * 1000)

        sig_sizes.append(len(signature))

        # Sanity check: jika verify gagal, ada bug serius
        if not valid:
            raise RuntimeError(f"ECDSA verify GAGAL pada iterasi {i}!")

    avg_sign   = sum(sign_times)   / num_samples
    avg_verify = sum(verify_times) / num_samples

    return {
        "avg_sign_ms"   : round(avg_sign,                              6),
        "avg_verify_ms" : round(avg_verify,                            6),
        "avg_total_ms"  : round(avg_sign + avg_verify,                 6),
        "std_sign_ms"   : round(statistics.stdev(sign_times),          6),
        "std_verify_ms" : round(statistics.stdev(verify_times),        6),
        "sig_size_bytes": int(sum(sig_sizes) / num_samples),
        "num_samples"   : num_samples,
    }


def benchmark_elgamal(keypair: dict, hash_name: str, msg_size: int,
                      num_samples: int) -> dict:
    """
    Mengukur rata-rata waktu sign + verify ElGamal untuk konfigurasi tertentu.

    Keypair diterima sebagai parameter (sudah di-generate di luar) karena
    ElGamal keygen mahal — lebih efisien generate sekali, pakai berkali-kali.

    Returns:
        Dict statistik yang sama strukturnya dengan benchmark_ecdsa()
    """
    sign_times   = []
    verify_times = []
    sig_sizes    = []

    for i in range(num_samples):
        message = generate_random_message(msg_size)

        # --- Ukur waktu signing ---
        t0 = time.perf_counter()
        signature = elgamal_sign(keypair, message, hash_name)
        sign_times.append((time.perf_counter() - t0) * 1000)

        # --- Ukur waktu verifikasi ---
        t0 = time.perf_counter()
        valid = elgamal_verify(keypair, message, signature, hash_name)
        verify_times.append((time.perf_counter() - t0) * 1000)

        sig_sizes.append(len(serialize_elgamal_signature(signature)))

        if not valid:
            raise RuntimeError(f"ElGamal verify GAGAL pada iterasi {i}!")

    avg_sign   = sum(sign_times)   / num_samples
    avg_verify = sum(verify_times) / num_samples

    return {
        "avg_sign_ms"   : round(avg_sign,                              6),
        "avg_verify_ms" : round(avg_verify,                            6),
        "avg_total_ms"  : round(avg_sign + avg_verify,                 6),
        "std_sign_ms"   : round(statistics.stdev(sign_times),          6),
        "std_verify_ms" : round(statistics.stdev(verify_times),        6),
        "sig_size_bytes": int(sum(sig_sizes) / num_samples),
        "num_samples"   : num_samples,
    }


# ===========================================================================
# BAGIAN 5: MAIN — jalankan semua benchmark dan simpan ke CSV
# ===========================================================================

def run_all_benchmarks():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    fieldnames = [
        "scheme", "key_size", "hash_name", "message_size_bytes",
        "avg_sign_ms", "avg_verify_ms", "avg_total_ms",
        "std_sign_ms", "std_verify_ms", "sig_size_bytes", "num_samples"
    ]

    rows = []
    total_configs = (
        len(ECDSA_CURVES)   * len(HASH_NAMES) * len(MESSAGE_SIZES) +
        len(ELGAMAL_PRIMES) * len(HASH_NAMES) * len(MESSAGE_SIZES)
    )
    current = 0

    # ---- ECDSA ----
    print("=" * 60)
    print("BENCHMARKING ECDSA")
    print("=" * 60)

    for curve_name in ECDSA_CURVES:
        for hash_name in HASH_NAMES:
            for msg_size in MESSAGE_SIZES:
                current += 1
                print(f"\n[{current}/{total_configs}] "
                      f"ECDSA | Curve={curve_name} | Hash={hash_name} | "
                      f"MsgSize={msg_size}B")

                result = benchmark_ecdsa(curve_name, hash_name, msg_size, NUM_SAMPLES)
                rows.append({
                    "scheme": "ECDSA", "key_size": curve_name,
                    "hash_name": hash_name, "message_size_bytes": msg_size,
                    **result
                })

                print(f"    Sign={result['avg_sign_ms']:.4f}ms ± {result['std_sign_ms']:.4f} | "
                      f"Verify={result['avg_verify_ms']:.4f}ms ± {result['std_verify_ms']:.4f} | "
                      f"Total={result['avg_total_ms']:.4f}ms | "
                      f"SigSize={result['sig_size_bytes']}B")

    # ---- ElGamal ----
    print("\n" + "=" * 60)
    print("BENCHMARKING ELGAMAL")
    print("=" * 60)

    # Generate semua keypair ElGamal di awal — operasi ini MAHAL (bisa menit-an)
    # karena melibatkan operasi eksponen dengan bilangan ratusan digit.
    print("\nPre-generating ElGamal keypairs (butuh waktu)...")
    elgamal_keypairs = {}
    for prime_name in ELGAMAL_PRIMES:
        print(f"  {prime_name}...", end=" ", flush=True)
        elgamal_keypairs[prime_name] = generate_elgamal_keypair(prime_name)
        print("done.")

    for prime_name in ELGAMAL_PRIMES:
        for hash_name in HASH_NAMES:
            for msg_size in MESSAGE_SIZES:
                current += 1
                print(f"\n[{current}/{total_configs}] "
                      f"ElGamal | Prime={prime_name} | Hash={hash_name} | "
                      f"MsgSize={msg_size}B")

                result = benchmark_elgamal(
                    elgamal_keypairs[prime_name], hash_name, msg_size, NUM_SAMPLES
                )
                rows.append({
                    "scheme": "ElGamal", "key_size": prime_name,
                    "hash_name": hash_name, "message_size_bytes": msg_size,
                    **result
                })

                print(f"    Sign={result['avg_sign_ms']:.4f}ms ± {result['std_sign_ms']:.4f} | "
                      f"Verify={result['avg_verify_ms']:.4f}ms ± {result['std_verify_ms']:.4f} | "
                      f"Total={result['avg_total_ms']:.4f}ms | "
                      f"SigSize={result['sig_size_bytes']}B")

    # Tulis semua hasil ke CSV
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"\n{'='*60}")
    print(f"Selesai! Hasil disimpan ke: {OUTPUT_FILE}")
    print(f"Total konfigurasi: {len(rows)}")
    print(f"{'='*60}")


if __name__ == "__main__":
    import sys
    print(f"Python: {sys.version}")
    print(f"Samples per kombinasi: {NUM_SAMPLES}")
    print(f"Ukuran pesan (bytes): {MESSAGE_SIZES}")
    print()
    run_all_benchmarks()
