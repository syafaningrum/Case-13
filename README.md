---

# Performance Benchmark of Digital Signatures: ECDSA vs ElGamal

Proyek ini bertujuan untuk menganalisis dan membandingkan performa skema tanda tangan digital berbasis **Elliptic Curve Cryptography (ECDSA)** dan **ElGamal**. Pengujian dilakukan secara komprehensif dengan mengukur **Computational Delay** (waktu pemrosesan) dan **Transmission Delay** (waktu pengiriman jaringan) menggunakan fungsi hash **SHA-256** dan **SHA-384** di lingkungan jaringan terdistribusi.

Proyek ini juga menginvestigasi dampak ukuran *plaintext* (pesan) serta ukuran kunci terhadap kedua jenis delay tersebut berdasarkan rata-rata minimal **100 sampel** per kombinasi parameter.

---

## 🛠️ Sistem & Arsitektur Pengujian

Untuk mendapatkan data latensi jaringan yang valid, pengujian dilakukan menggunakan dua mesin *Virtual Machine* (VM) terpisah untuk mengisolasi komponen delay secara murni:

```
+---------------------------------+               +---------------------------------+
|        VM CLIENT (Linux)        |               |        VM SERVER (Linux)        |
|          172.20.0.106           |               |          172.20.0.103           |
+---------------------------------+               +---------------------------------+
|  1. Pre-sign 100 pesan          |               |  1. Terima Payload JSON         |
|  2. Catat t_start               |  TCP (5005)   |  2. Kirim ACK SEGERA <----------|--- Isolasi Delay
|  3. Kirim JSON Payload -------->|-------------->|  3. Jalankan ecdsa/elgamal      |    Jaringan murni
|  4. Terima ACK <----------------|<--------------|     verify                      |
|  5. Catat t_end                 |               |  4. Log data ke CSV             |
+---------------------------------+               +---------------------------------+
     Transmission Delay = t_end - t_start

```

### 🛰️ Metodologi Isolasi Pengukuran Delay

1. **Transmission Delay (Client Side):** Diukur pada sisi klien dari tepat sebelum data dikirim hingga ACK diterima dari server. Untuk mencegah waktu komputasi tanda tangan memengaruhi latensi jaringan, klien melakukan proses **pre-sign** terhadap 100 pesan terlebih dahulu sebelum transmisi dimulai.
2. **Computational Delay (Server Side):** Server dikonfigurasi untuk mengirimkan **ACK segera** setelah menerima *payload* penuh, baru kemudian melakukan fungsi verifikasi. Hal ini menjamin bahwa waktu komputasi verifikasi di server tidak ikut terhitung ke dalam *transmission delay* yang diukur klien.
3. **Optimasi Soket:** Menggunakan mekanisme *Length-Prefixed Framing* (header 4-byte big-endian untuk panjang data) guna mengatasi fragmentasi TCP, serta mengaktifkan opsi `TCP_NODELAY` untuk menonaktifkan *Nagle's Algorithm* agar paket-paket kecil (seperti ACK) dikirim instan tanpa penundaan *buffering*.

---

## 📊 Analisis Hasil Eksperimen & Penjelasan Grafik

Berikut adalah analisis mendalam dari grafik hasil benchmark yang diperoleh:

### 1. Perbandingan Computational Delay (SHA-256 & SHA-384)

Grafik di bawah ini menunjukkan rata-rata total waktu komputasi ($t_{sign} + t_{verify}$) dalam milidetik (ms) berdasarkan ukuran pesan.

| Hasil Benchmark SHA-256 | Hasil Benchmark SHA-384 |
| --- | --- |
|  |  |

#### 📝 Analisis Grafik Komputasi:

* **Dominasi Efisiensi ECDSA:** ECDSA menyelesaikan proses sign & verify dalam waktu jauh di bawah **1 ms** untuk semua ukuran kurva (`secp192r1`, `secp256r1`, `secp384r1`). Sebaliknya, ElGamal membutuhkan waktu komputasi yang masif, melonjak hingga **~192 ms** pada ukuran kunci 3072-bit.
* **Anomali Optimasi Kunci ECDSA:** Berdasarkan grafik, kurva `secp256r1` (~0.10 ms) menunjukkan performa yang **lebih cepat** dibandingkan kurva yang lebih kecil seperti `secp192r1` (~0.47 ms). Hal ini terjadi karena `secp256r1` (NIST P-256) merupakan standar industri global yang memiliki jalur kode instruksi assembly yang sangat teroptimasi (*hardcoded field arithmetic*) pada pustaka kriptografi native (OpenSSL backend), sedangkan `secp192r1` tidak mendapatkan optimasi sedalam itu.
* **Skalabilitas Kunci ElGamal:** Komputasi ElGamal meningkat secara eksponensial seiring bertambahnya ukuran prime (`1024-bit` $\rightarrow$ ~10 ms, `2048-bit` $\rightarrow$ ~63 ms, `3072-bit` $\rightarrow$ ~192 ms). Hal ini disebabkan oleh sifat implementasi manual ElGamal *from scratch* yang mengandalkan operasi eksponensial modular (`pow(g, x, p)`) pada bilangan bulat raksasa (*Big Integer*), yang secara komputasi jauh lebih berat dibandingkan operasi matematika berbasis titik kurva eliptik pada ECDSA.

---

### 2. Summary Heatmap: Rata-Rata Computational Delay (Pesan 150 Byte)


Heatmap ini merangkum peta performa komputasi secara spasial pada ukuran pesan penengah (150 Byte) untuk melihat perbandingan kontras antarschema.

#### 📝 Analisis Grafik Heatmap:

* Grafik ini mempertegas perbedaan performa orde magnitudo (*orders of magnitude*). Perpindahan dari skema ECDSA tercepat (`secp256r1` @ 0.101 ms) ke skema ElGamal terberat (`3072-bit` @ 193.826 ms) menunjukkan perbedaan efisiensi waktu hingga **~1.900 kali lipat**.

---

### 3. Perbandingan Transmission Delay (Latensi Komunikasi)

Grafik berikut menampilkan waktu pengiriman payload tanda tangan digital dari klien ke server melalui jaringan TCP.

| Komparasi Makro Delay Transmisi | Analisis Mikro Tren Jaringan |
| --- | --- |
|  |  |

#### 📝 Analisis Grafik Transmisi:

* **Overhead Payload ElGamal:** *Transmission delay* untuk skema ElGamal berada di kisaran **~62 ms**, sedangkan ECDSA sangat tipis berada di kisaran **~0.33 ms**.
* **Penyebab Utama Selisih Latensi:** Hal ini terjadi karena ElGamal mentransmisikan parameter kunci publik berupa struktur data teks JSON berisi representasi biner (*hex string*) dari variabel prime raksasa $p$, generator $g$, dan kunci $y$ ke server pada setiap koneksi. Ukuran string teks yang besar ini meningkatkan ukuran *payload* jaringan secara drastis, sehingga membutuhkan waktu serialisasi, transmisi soket, dan deserialisasi yang jauh lebih lama. Sementara itu, ECDSA mentransmisikan kunci publik dan signature dalam bentuk byte terkompresi standar DER biner yang sangat ringkas.
* **Fluktuasi Mikro pada ECDSA:** Pada grafik *zoomed-in* (sisi kiri `image_5126cc.jpg`), terlihat delay transmisi ECDSA berosilasi naik-turun dalam rentang mikro yang sangat kecil (0.31 ms - 0.36 ms). Fluktuasi ini bukanlah tren sistematis, melainkan gangguan latensi acak (*network jitter*) pada tumpukan protokol OS (*TCP/IP stack execution*) dan kondisi antrean jaringan internal VM saat pengujian.

---

### 4. Dampak Ukuran Plaintext (Dua Variabel Delay)

Eksperimen ini juga secara khusus mengukur pengaruh ukuran pesan dari **50 Byte hingga 250 Byte**.

#### 📝 Analisis Dampak Ukuran Pesan:

* **Sifat Flat pada Grafik:** Baik pada grafik komputasi maupun transmisi, perubahan ukuran pesan dari 50 ke 250 Byte menghasilkan garis tren yang **hampir sepenuhnya horizontal (konstan)**.
* **Alasan Ilmiah Kriptografi:** Hal ini membuktikan prinsip dasar arsitektur tanda tangan digital: **proses asimetris (ECC/ElGamal) tidak pernah menandatangani dokumen mentah, melainkan menandatangani hasil *hash digest* dari pesan tersebut**. Sesuai standar, SHA-256 akan selalu menghasilkan output tetap sebesar 32 Byte dan SHA-384 menghasilkan 48 Byte, tidak peduli seberapa besar pesan inputnya. Selisih waktu untuk melakukan hashing pada pesan 50 Byte vs 250 Byte berada pada skala nanosekon, sehingga pengaruh penambahan ukuran *plaintext* dalam skala ini menjadi tidak signifikan (*negligible*) terhadap total delay.

---

### 5. Pengaruh Fungsi Hash: SHA-256 vs SHA-384

Melalui visualisasi bar chart berkelompok (`image_51274b.png`), kita dapat melihat komparasi mikro penggunaan fungsi hash.

* Penggunaan **SHA-384** memberikan sedikit kontribusi penambahan waktu komputasi dan ukuran bit transmisi yang sedikit lebih tinggi dibandingkan **SHA-256**, terutama pada skema ElGamal. Hal ini logis karena SHA-384 memproses blok data yang lebih besar (1024-bit blok vs 512-bit blok pada SHA-256) dan menghasilkan ukuran *digest* yang lebih panjang (48 Byte vs 32 Byte), menambahkan sedikit beban bagi komputasi aritmatika modular berikutnya.

---

## 📌 Kesimpulan Utama (Takeaways)

1. **ECDSA Unggul Mutlak:** Dari segi efisiensi komputasi dan penggunaan bandwidth jaringan, ECDSA jauh melampaui ElGamal. Pemanfaatan matematika kurva eliptik memungkinkan ECDSA menawarkan tingkat keamanan yang setara dengan RSA/ElGamal namun dengan ukuran kunci yang jauh lebih ringkas.
2. **Faktor Implementasi Native:** Penggunaan kurva standar industri seperti `secp256r1` sangat direkomendasikan karena dukungan optimasi pada level instruksi tingkat rendah (*low-level assembly*) oleh library kriptografi modern.
3. **Ukuran Pesan Jaringan:** Untuk dokumen berukuran kecil hingga menengah, ukuran pesan tidak memengaruhi delay komputasi skema tanda tangan digital, karena beban kerja utama berpusat pada kalkulasi matematis asimetris dari nilai *hash fixed-length*.

---

## 🚀 Cara Menjalankan Kode Program

### 1. Prasyarat

Pastikan dependensi library `cryptography` sudah terinstal:

```bash
pip install cryptography

```

### 2. Langkah Pengujian

1. **Jalankan Uji Komputasi Mandiri:**
```bash
python benchmark_computation.py

```


Hasil pengujian komputasi murni akan diekspor ke file `results/computational_delay.csv`.
2. **Jalankan Pengujian Jaringan Berdistribusi:**
* Di sisi **VM Server (172.20.0.103)**, jalankan server pembaca:
```bash
python server.py

```


* Di sisi **VM Client (172.20.0.106)**, jalankan pengirim payload:
```bash
python client.py

```




Data delay transmisi dan log verifikasi server masing-masing akan tersimpan di direktori `results/`.
