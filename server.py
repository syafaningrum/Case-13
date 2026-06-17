"""
server.py
---------
Dijalankan di VM Server (172.20.0.103).

Alur kerja per koneksi:
  1. Terima payload JSON dari client (berisi pesan, signature, public key)
  2. Kirim ACK SEGERA ke client — ini PENTING karena client mengukur
     transmission delay dari "mulai kirim" sampai "terima ACK".
     ACK dikirim SEBELUM verifikasi agar delay verifikasi tidak ikut terhitung.
  3. Setelah ACK terkirim, baru lakukan verifikasi signature.
  4. Log hasil verifikasi + waktu verify ke CSV.

Port: 5005
Bind: 0.0.0.0 (semua interface)
"""

# ===========================================================================
# IMPORT LIBRARY
# ===========================================================================
import base64
import csv
import hashlib
import json
import os
import socket
import struct
import sys
import time
import traceback

# Untuk ECDSA: pakai library `cryptography`
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_der_public_key
from cryptography.exceptions import InvalidSignature


# ===========================================================================
# BAGIAN 1: IMPLEMENTASI ECDSA (untuk keperluan verifikasi di server)
# ===========================================================================
# Server hanya perlu VERIFY (bukan sign), jadi yang diperlukan:
#   - Rekonstruksi public key dari bytes DER yang dikirim client
#   - Fungsi verifikasi signature
# ===========================================================================

# Pemetaan nama hash ke CLASS hash dari library cryptography
# Pakai CLASS (bukan instance) karena nanti dipanggil dengan () saat dipakai
ECDSA_HASH_MAP = {
    "SHA-256": hashes.SHA256,
    "SHA-384": hashes.SHA384,
}


def ecdsa_verify(public_key, message: bytes, signature: bytes,
                 hash_name: str) -> bool:
    """
    Memverifikasi tanda tangan ECDSA.

    Proses verifikasi (dilakukan otomatis oleh library):
      1. Pesan di-hash: H = hash(message)
      2. Signature (r, s) di-decode dari format DER
      3. Dihitung ulang titik dari persamaan kurva eliptik
      4. Jika cocok dengan r yang ada di signature → valid

    Args:
        public_key  : Objek public key dari library cryptography
        message     : Pesan asli (bytes) — harus identik dengan yang di-sign
        signature   : Signature dalam format DER (bytes)
        hash_name   : Hash yang dipakai saat signing ('SHA-256' atau 'SHA-384')

    Returns:
        True jika signature valid, False jika tidak
    """
    if hash_name not in ECDSA_HASH_MAP:
        raise ValueError(f"Hash tidak dikenal: {hash_name}")

    try:
        # Jika tidak valid, library raise InvalidSignature (bukan return False)
        public_key.verify(
            signature,
            message,
            ec.ECDSA(ECDSA_HASH_MAP[hash_name]())
        )
        return True
    except InvalidSignature:
        return False


def reconstruct_ecdsa_public_key(pubkey_b64: str):
    """
    Merekonstruksi public key ECDSA dari string base64-encoded DER.

    Client mengirim public key dalam format DER yang di-encode ke base64
    supaya bisa masuk ke payload JSON (JSON tidak bisa menyimpan bytes mentah).

    DER (Distinguished Encoding Rules) adalah format biner standar untuk
    menyimpan kunci kriptografi.

    Args:
        pubkey_b64 : String base64 dari DER bytes public key

    Returns:
        Objek public key dari library cryptography
    """
    der_bytes = base64.b64decode(pubkey_b64)
    return load_der_public_key(der_bytes, backend=default_backend())


# ===========================================================================
# BAGIAN 2: IMPLEMENTASI ELGAMAL (untuk keperluan verifikasi di server)
# ===========================================================================
# ElGamal diimplementasi manual (from scratch) karena library standar Python
# tidak menyediakan ElGamal signature (hanya ElGamal encryption).
#
# Rumus verifikasi ElGamal:
#   g^{H(m)} ≡ y^r * r^s (mod p)
#
# Server hanya butuh (p, g, y) untuk verifikasi — private key x TIDAK diperlukan.
# ===========================================================================

# Prime standar untuk ElGamal (sama yang dipakai client saat keygen)
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

ELGAMAL_PRIME_MAP = {
    "1024-bit": PRIME_1024,
    "2048-bit": PRIME_2048,
    "3072-bit": PRIME_3072,
}

# Pemetaan nama hash ke fungsi hashlib (untuk ElGamal yang manual)
ELGAMAL_HASH_MAP = {
    "SHA-256": hashlib.sha256,
    "SHA-384": hashlib.sha384,
}


def elgamal_verify(keypair: dict, message: bytes, signature: tuple,
                   hash_name: str) -> bool:
    """
    Memverifikasi tanda tangan ElGamal.

    Rumus: g^{H(m)} ≡ y^r * r^s (mod p)

    Kenapa rumus ini bekerja? (derivasi matematis)
      Dari proses signing, kita tahu: s = k^{-1}*(H - x*r) mod (p-1)
      → k*s ≡ H - x*r (mod p-1)
      → H ≡ x*r + k*s (mod p-1)

      Dengan Fermat's little theorem (g^{p-1} ≡ 1 mod p):
      g^H = g^{x*r + k*s} = (g^x)^r * (g^k)^s = y^r * r^s (mod p)

    Args:
        keypair   : Dict berisi p, g, y (public key) — x TIDAK diperlukan
        message   : Pesan asli (bytes)
        signature : Tuple (r, s)
        hash_name : Hash yang dipakai saat signing

    Returns:
        True jika valid, False jika tidak
    """
    if hash_name not in ELGAMAL_HASH_MAP:
        raise ValueError(f"Hash tidak dikenal: {hash_name}")

    p, g, y = keypair["p"], keypair["g"], keypair["y"]
    r, s = signature

    # Validasi range r dan s sebelum operasi berat
    if not (0 < r < p):
        return False
    if not (0 < s < p - 1):
        return False

    # Hash pesan → integer (agar bisa dioperasikan secara modular)
    H = int.from_bytes(ELGAMAL_HASH_MAP[hash_name](message).digest(), 'big')

    # Cek persamaan ElGamal
    lhs = pow(g, H, p)                       # sisi kiri: g^H mod p
    rhs = (pow(y, r, p) * pow(r, s, p)) % p  # sisi kanan: y^r * r^s mod p

    return lhs == rhs


def deserialize_elgamal_signature(data: bytes) -> tuple:
    """
    Mengubah bytes kembali menjadi signature (r, s).

    Format yang diharapkan (sesuai serialisasi di client):
      [4 byte: panjang r][r dalam bytes][4 byte: panjang s][s dalam bytes]

    Kenapa perlu deserialisasi manual?
      Integer Python bisa berukuran ratusan bytes (untuk prime 3072-bit).
      Tidak ada cara langsung menyimpan integer besar ke dalam byte stream
      tanpa informasi panjangnya.
    """
    r_len = int.from_bytes(data[0:4], 'big')
    r = int.from_bytes(data[4:4 + r_len], 'big')

    offset = 4 + r_len
    s_len = int.from_bytes(data[offset:offset + 4], 'big')
    s = int.from_bytes(data[offset + 4:offset + 4 + s_len], 'big')

    return (r, s)


def reconstruct_elgamal_keypair(keypair_b64: str) -> dict:
    """
    Merekonstruksi parameter publik ElGamal dari string base64-encoded JSON.

    Client mengirim p, g, y sebagai hex string dalam JSON (karena JSON tidak
    mendukung integer sebesar ini secara native). Private key x TIDAK dikirim
    — server tidak membutuhkannya, dan mengirimnya adalah kebocoran keamanan.

    Args:
        keypair_b64 : String base64 dari JSON berisi p, g, y (hex strings)

    Returns:
        Dict berisi p, g, y sebagai integer Python, plus prime_name
    """
    kp = json.loads(base64.b64decode(keypair_b64).decode("utf-8"))
    return {
        "p"         : int(kp["p"], 16),   # hex string → integer
        "g"         : int(kp["g"], 16),
        "y"         : int(kp["y"], 16),
        "prime_name": kp["prime_name"],
    }


# ===========================================================================
# BAGIAN 3: UTILITAS SOCKET / FRAMING
# ===========================================================================
# TCP tidak menjamin bahwa satu send() = satu recv() yang utuh.
# Data bisa terpecah menjadi beberapa chunk (disebut "fragmentation").
# Oleh karena itu kita pakai "length-prefixed framing":
#   - Sebelum data, kirim 4 byte yang menyatakan panjang data.
#   - Penerima baca 4 byte dulu, lalu baca tepat sejumlah itu.
# ===========================================================================

BUFFER_SIZE = 65536   # 64 KB per recv() — ukuran buffer baca socket
ACK_MESSAGE = b"ACK"  # Pesan ACK yang dikirim ke client (3 bytes)


def recv_exact(conn: socket.socket, n: int) -> bytes:
    """
    Menerima TEPAT n bytes dari socket, menangani fragmentasi TCP.

    Tanpa fungsi ini, conn.recv(n) mungkin hanya mengembalikan sebagian
    data jika paket terpecah di jaringan.
    """
    data = b""
    while len(data) < n:
        chunk = conn.recv(min(BUFFER_SIZE, n - len(data)))
        if not chunk:
            raise ConnectionError("Koneksi ditutup client sebelum data lengkap.")
        data += chunk
    return data


def recv_payload(conn: socket.socket) -> dict:
    """
    Menerima payload dengan format length-prefixed dari socket.

    Format:
      [4 byte big-endian: panjang JSON][JSON bytes]

    'big-endian' artinya byte paling signifikan di posisi paling kiri.
    Contoh: panjang 1000 = 0x000003E8 → bytes: [0x00, 0x00, 0x03, 0xE8]

    Returns:
        Dict hasil parse JSON
    """
    # Baca 4 byte header untuk tahu panjang payload
    header = recv_exact(conn, 4)
    payload_len = struct.unpack("!I", header)[0]  # "!I" = big-endian unsigned int

    # Baca payload JSON sejumlah payload_len byte
    payload_bytes = recv_exact(conn, payload_len)
    return json.loads(payload_bytes.decode("utf-8"))


# ===========================================================================
# BAGIAN 4: HANDLER KONEKSI
# ===========================================================================

def handle_connection(conn: socket.socket, addr, log_writer):
    """
    Menangani satu koneksi masuk dari client.

    URUTAN KRITIS — jangan dibalik:
      1. Terima payload (pesan + signature + public key)
      2. Kirim ACK ← client menghentikan timer tepat setelah ini
      3. Verifikasi signature ← waktunya dicatat di log server

    Kenapa ACK dikirim SEBELUM verifikasi?
      Karena kita ingin mengukur murni transmission delay (waktu transfer
      data di jaringan), BUKAN transmission + computation delay.
      Jika ACK dikirim setelah verifikasi, angka delay di client akan
      mencakup waktu verifikasi juga — dan itu salah untuk tujuan kita.
    """
    try:
        # LANGKAH 1: Terima payload dari client
        payload = recv_payload(conn)

        # LANGKAH 2: Kirim ACK SEGERA (sebelum verifikasi!)
        # conn.sendall() memastikan semua bytes terkirim (tidak terpotong)
        conn.sendall(ACK_MESSAGE)

        # LANGKAH 3: Parse field dari payload
        scheme     = payload["scheme"]       # "ECDSA" atau "ElGamal"
        hash_name  = payload["hash_name"]    # "SHA-256" atau "SHA-384"
        key_size   = payload["key_size"]     # nama kurva/prime
        msg_size   = payload["msg_size"]     # ukuran pesan dalam bytes
        sample_idx = payload["sample_idx"]   # indeks sample (0..99)

        # Decode pesan dari base64 (JSON hanya bisa menyimpan teks, bukan bytes)
        message = base64.b64decode(payload["message_b64"])

        # LANGKAH 4: Verifikasi signature — ukur waktunya
        t_verify_start = time.perf_counter()

        if scheme == "ECDSA":
            # Rekonstruksi public key dari DER bytes yang di-encode base64
            public_key = reconstruct_ecdsa_public_key(payload["pubkey_b64"])
            # Signature ECDSA dalam format DER bytes
            signature  = base64.b64decode(payload["sig_b64"])
            valid = ecdsa_verify(public_key, message, signature, hash_name)

        elif scheme == "ElGamal":
            # Rekonstruksi parameter publik (p, g, y) dari JSON base64
            keypair   = reconstruct_elgamal_keypair(payload["pubkey_b64"])
            # Signature ElGamal adalah (r, s) yang perlu di-deserialize
            sig_bytes = base64.b64decode(payload["sig_b64"])
            signature = deserialize_elgamal_signature(sig_bytes)
            valid = elgamal_verify(keypair, message, signature, hash_name)

        else:
            raise ValueError(f"Skema tidak dikenal: {scheme}")

        verify_time_ms = (time.perf_counter() - t_verify_start) * 1000

        # LANGKAH 5: Log hasil ke CSV
        log_writer.writerow({
            "timestamp"      : time.strftime("%Y-%m-%d %H:%M:%S"),
            "client_addr"    : addr[0],
            "scheme"         : scheme,
            "key_size"       : key_size,
            "hash_name"      : hash_name,
            "msg_size_bytes" : msg_size,
            "sample_idx"     : sample_idx,
            "verify_valid"   : valid,
            "verify_time_ms" : round(verify_time_ms, 6),
        })

        print(f"  [{addr[0]}] {scheme}/{key_size}/{hash_name} "
              f"msg={msg_size}B sample={sample_idx} "
              f"valid={valid} verify={verify_time_ms:.3f}ms")

    except Exception as e:
        print(f"  ERROR dari {addr}: {e}")
        traceback.print_exc()
    finally:
        # Selalu tutup koneksi setelah selesai (bahkan jika ada error)
        conn.close()


# ===========================================================================
# BAGIAN 5: KONFIGURASI SERVER & MAIN LOOP
# ===========================================================================

HOST       = "0.0.0.0"   # Dengarkan di semua interface jaringan
PORT       = 5005
OUTPUT_DIR = "results"
SERVER_LOG = os.path.join(OUTPUT_DIR, "server_verify_log.csv")


def run_server():
    """
    Menjalankan server TCP yang terus mendengarkan koneksi client.

    Server berjalan single-threaded (satu koneksi diproses satu per satu).
    Ini tidak masalah karena client juga mengirim satu per satu secara serial.
    """
    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print(f"{'='*60}")
    print(f"SERVER Digital Signature Benchmark")
    print(f"Bind : {HOST}:{PORT}")
    print(f"Log  : {SERVER_LOG}")
    print(f"{'='*60}")
    print("Tekan Ctrl+C untuk berhenti.\n")

    log_fields = [
        "timestamp", "client_addr", "scheme", "key_size", "hash_name",
        "msg_size_bytes", "sample_idx", "verify_valid", "verify_time_ms"
    ]

    with open(SERVER_LOG, "w", newline="", encoding="utf-8") as log_file:
        log_writer = csv.DictWriter(log_file, fieldnames=log_fields)
        log_writer.writeheader()
        log_file.flush()

        # Buat socket TCP (AF_INET = IPv4, SOCK_STREAM = TCP)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
            # SO_REUSEADDR: izinkan rebind port yang baru saja dilepas
            # (berguna saat server di-restart cepat)
            srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            srv.bind((HOST, PORT))
            srv.listen(128)  # 128 = backlog koneksi yang menunggu

            print(f"Server mendengarkan di {HOST}:{PORT}...")

            while True:
                try:
                    # Tunggu koneksi masuk (blocking)
                    conn, addr = srv.accept()

                    # TCP_NODELAY: nonaktifkan Nagle's algorithm
                    # Nagle's algorithm menunda pengiriman paket kecil sampai
                    # ada data lebih. Kita nonaktifkan agar ACK (3 bytes)
                    # dikirim segera tanpa penundaan.
                    conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

                    print(f"Koneksi dari {addr[0]}:{addr[1]}")
                    handle_connection(conn, addr, log_writer)

                    # Flush log ke disk setiap koneksi selesai
                    log_file.flush()

                except KeyboardInterrupt:
                    print("\nServer dihentikan.")
                    break
                except Exception as e:
                    print(f"Error accept: {e}")
                    continue


if __name__ == "__main__":
    run_server()
