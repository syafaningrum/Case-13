---

# Performance Benchmark of Digital Signatures: ECDSA vs ElGamal

Proyek ini bertujuan untuk menganalisis dan membandingkan performa skema tanda tangan digital berbasis **Elliptic Curve Cryptography (ECDSA)** dan **ElGamal**. Pengujian dilakukan secara komprehensif dengan mengukur **Computational Delay** (waktu pemrosesan) dan **Transmission Delay** (waktu komunikasi jaringan) menggunakan fungsi hash **SHA-256** dan **SHA-384**.

Proyek ini juga secara mendalam menginvestigasi dampak ukuran *plaintext* (pesan) serta ukuran kunci keamanan terhadap kedua jenis delay tersebut berdasarkan rata-rata pengujian minimal **100 sampel** per kombinasi parameter.

---

## 🛠️ Sistem & Arsitektur Pengujian

Untuk mendapatkan data latensi jaringan yang murni dan akurat, pengujian dilakukan menggunakan dua mesin *Virtual Machine* (VM) terpisah di dalam jaringan lokal untuk mengisolasi komponen delay:

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

1. **Transmission Delay (Client Side):** Diukur pada sisi klien dari tepat sebelum data dikirim hingga ACK diterima dari server. Untuk mencegah waktu komputasi pembuatan signature memengaruhi penilaian latensi jaringan, klien melakukan proses **pre-sign** terhadap 100 pesan terlebih dahulu sebelum transmisi dimulai.
2. **Computational Delay (Server Side):** Server dikonfigurasi untuk mengirimkan **ACK segera** setelah menerima *payload* penuh, baru kemudian mengeksekusi fungsi verifikasi. Hal ini menjamin bahwa waktu komputasi verifikasi di server tidak ikut tercampur ke dalam *transmission delay* yang diukur klien.
3. **Optimasi Jaringan Tingkat Rendah:** Menggunakan mekanisme *Length-Prefixed Framing* (header 4-byte big-endian untuk penanda panjang data) guna menangani fragmentasi TCP, serta mengaktifkan opsi `TCP_NODELAY` untuk menonaktifkan *Nagle's Algorithm* agar paket konfirmasi ACK (3 bytes) dikirim seketika tanpa penundaan *buffering* sistem operasi.

---

## 📊 Analisis Hasil Eksperimen & Penjelasan Grafik

### 1. Analisis Makro Tren Kurva Linier & Heatmap

| Komputasi vs Ukuran Pesan (SHA-256) | Komputasi vs Ukuran Pesan (SHA-384) |
| --- | --- |
|  |  |

* **Dominasi Efisiensi ECDSA:** ECDSA menyelesaikan proses sign & verify dalam waktu jauh di bawah **1 ms** untuk semua ukuran kurva (`secp192r1`, `secp256r1`, `secp384r1`). Sebaliknya, ElGamal membutuhkan waktu komputasi yang masif, melonjak hingga **~192 ms** pada ukuran kunci 3072-bit.
* **Anomali Optimasi Kunci ECDSA:** Kurva `secp256r1` (~0.10 ms) terbukti **lebih cepat** dibandingkan kurva yang secara matematis lebih kecil seperti `secp192r1` (~0.47 ms). Hal ini terjadi karena `secp256r1` (NIST P-256) merupakan standar industri global yang memiliki jalur kode instruksi assembly yang sangat teroptimasi (*hardcoded field arithmetic*) pada pustaka kriptografi native (`cryptography` berbasis OpenSSL backend), sedangkan `secp192r1` tidak mendapatkan optimasi sedalam itu.
* **Skalabilitas Kunci ElGamal:** Komputasi ElGamal meningkat secara eksponensial seiring bertambahnya ukuran prime (`1024-bit` $\rightarrow$ ~10 ms, `2048-bit` $\rightarrow$ ~63 ms, `3072-bit` $\rightarrow$ ~192 ms). Hal ini disebabkan oleh sifat implementasi manual ElGamal *from scratch* yang mengandalkan operasi eksponensial modular (`pow(g, x, p)`) pada bilangan bulat raksasa (*Big Integer*), yang secara komputasi jauh lebih berat dibandingkan operasi matematika berbasis titik kurva eliptik pada ECDSA.

| Ringkasan Spasial Kinerja Jaringan (150B) | Tren Komparasi Makro Transmisi |
| --- | --- |
|  |  |

* **Perbedaan Orde Magnitudo:** Grafik heatmap di atas mempertegas jurang efisiensi waktu komputasi. Perpindahan dari skema ECDSA tercepat (`secp256r1` @ 0.101 ms) ke skema ElGamal terberat (`3072-bit` @ 193.826 ms) menunjukkan perbedaan performa efisiensi hingga **~1.900 kali lipat**.

---

### 2. Analisis Mikro Eksak Berbasis Bar Chart Berkelompok (Skala Logaritmik)

Penggunaan **Skala Logaritmik (Log Scaled)** pada sumbu Y ($10^{-1}$ hingga $10^3$) di bawah ini sangat krusial untuk menjembatani perbedaan nilai yang sangat kontras antara ECDSA dan ElGamal sehingga kedua data tetap dapat divisualisasikan dengan jelas.

| Detail Batang Komputasi — SHA-256 | Detail Batang Komputasi — SHA-384 |
| --- | --- |
|  |  |

* **Sifat Konstan Lintas Ukuran Plaintext:** Jika diperhatikan pada setiap kluster ukuran pesan (50B hingga 250B), tinggi batang diagram untuk masing-masing skema dan ukuran kunci berada pada level yang **hampir sepenuhnya horizontal (konstan)**. Hal ini mengonfirmasi secara empiris bahwa penambahan ukuran *plaintext* dalam skala ini tidak mendikte performa komputasi asimetris karena operasi kriptografi bertumpu pada *fixed-length hash digest*.

| Detail Batang Transmisi — SHA-256 | Detail Batang Transmisi — SHA-384 |
| --- | --- |
|  |  |

* **Overhead Jaringan Parameter Kunci ElGamal:** Berbeda dengan ECDSA yang latensi transmisinya tetap sangat rendah di seluruh ukuran kurva, ElGamal menunjukkan peningkatan *transmission delay* yang sangat signifikan seiring membesarnya ukuran bit kunci publik (`1024-bit` $\rightarrow$ ~7 ms, `2048-bit` $\rightarrow$ ~44 ms, `3072-bit` $\rightarrow$ ~134 ms hingga ~137 ms).
* **Akar Penyebab Efek Ukuran Kunci terhadap Komunikasi:** ElGamal mengirimkan parameter kunci publik berupa teks biner JSON yang berisi nilai prime $p$, generator $g$, dan public key $y$ yang dikonversi ke string heksadesimal. Ketika ukuran kunci naik menjadi 3072-bit, nilai $p$ dan $y$ menjadi representasi angka raksasa (~925 digit desimal). Akibatnya, ukuran *payload data packet* yang harus ditransmisikan melalui soket TCP membengkak drastis. Latensi transmisi ElGamal meningkat secara eksponensial bukan karena ukuran pesannya, melainkan karena **ukuran parameter kuncinya**.

---

### 3. Pengaruh Fungsi Hash: SHA-256 vs SHA-384

| Detail Tren Perubahan Mikro Jaringan | Distribusi Efek Fungsi Hash |
| --- | --- |
|  |  |

* **Beban Tambahan SHA-384:** Penggunaan **SHA-384** memberikan sedikit kontribusi penambahan waktu komputasi dan latensi transmisi yang sedikit lebih tinggi dibandingkan **SHA-256**, terutama pada skema ElGamal. Hal ini logis karena SHA-384 memproses blok data yang lebih besar (1024-bit blok vs 512-bit blok pada SHA-256) dan menghasilkan ukuran *digest* yang lebih panjang (48 Byte vs 32 Byte), menambahkan sedikit beban bagi komputasi aritmatika modular berikutnya.
* **Fluktuasi Mikro pada ECDSA:** Pada grafik transmisi mikro ECDSA (sisi kiri `image_5126cc.jpg`), terlihat delay berosilasi naik-turun dalam rentang mikro yang sangat kecil (0.31 ms - 0.36 ms). Fluktuasi ini bukanlah tren sistematis, melainkan gangguan latensi acak (*network jitter*) pada tumpukan protokol OS (*TCP/IP stack execution*) dan kondisi antrean antarmuka jaringan internal VM saat pengujian.

---

## 📋 Data Tabulasi Hasil Eksperimen (Eksak)

Seluruh angka di bawah ini bersumber langsung dari hasil rata-rata pengujian dan dapat disalin secara langsung untuk kebutuhan penyusunan dokumen ilmiah.

### 1. Tabel Ringkasan Umum Performa (Pesan = 150 Bytes)

| Skema Kriptografi | Ukuran Kunci / Kurva | Computational Delay (SHA-256) [ms] | Computational Delay (SHA-384) [ms] | Transmission Delay (SHA-256) [ms] | Transmission Delay (SHA-384) [ms] |
| --- | --- | --- | --- | --- | --- |
| **ECDSA** | secp192r1 | 0.469 | 0.475 | 0.280 | 0.250 |
| **ECDSA** | secp256r1 | 0.101 | 0.101 | 0.200 | 0.190 |
| **ECDSA** | secp384r1 | 0.839 | 0.839 | 0.550 | 0.560 |
| **ElGamal** | 1024-bit | 10.079 | 10.383 | 6.870 | 7.190 |
| **ElGamal** | 2048-bit | 62.558 | 63.751 | 43.780 | 45.010 |
| **ElGamal** | 3072-bit | 191.654 | 193.826 | 134.870 | 136.980 |

---

### 2. Tabel Detail: Computational Delay (Sign + Verify)

#### A. Menggunakan Fungsi Hash: SHA-256
| ![Computational Delay Grouped SHA-256](assets/Computational%20Delay%20SHA-256.jpeg) |

| Skema | Ukuran Kunci / Kurva | 50 Bytes | 100 Bytes | 150 Bytes | 200 Bytes | 250 Bytes | Rata-Rata |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **ECDSA** | secp192r1 | 0.48 | 0.47 | 0.47 | 0.47 | 0.47 | **0.472** |
| **ECDSA** | secp256r1 | 0.10 | 0.10 | 0.10 | 0.10 | 0.10 | **0.100** |
| **ECDSA** | secp384r1 | 0.84 | 0.84 | 0.84 | 0.84 | 0.84 | **0.840** |
| **ElGamal** | 1024-bit | 10.04 | 10.05 | 10.01 | 10.03 | 9.99 | **10.024** |
| **ElGamal** | 2048-bit | 62.93 | 62.69 | 62.63 | 62.60 | 62.51 | **62.672** |
| **ElGamal** | 3072-bit | 191.95 | 191.86 | 191.86 | 192.14 | 192.36 | **192.034** |

#### B. Menggunakan Fungsi Hash: SHA-384
| ![Computational Delay Grouped SHA-384](assets/Computational%20Delay%20SHA-384.jpeg) |

| Skema | Ukuran Kunci / Kurva | 50 Bytes | 100 Bytes | 150 Bytes | 200 Bytes | 250 Bytes | Rata-Rata |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **ECDSA** | secp192r1 | 0.48 | 0.47 | 0.47 | 0.47 | 0.47 | **0.472** |
| **ECDSA** | secp256r1 | 0.10 | 0.10 | 0.10 | 0.10 | 0.10 | **0.100** |
| **ECDSA** | secp384r1 | 0.85 | 0.84 | 0.84 | 0.84 | 0.84 | **0.842** |
| **ElGamal** | 1024-bit | 10.35 | 10.33 | 10.35 | 10.35 | 10.36 | **10.348** |
| **ElGamal** | 2048-bit | 63.70 | 63.68 | 63.68 | 63.75 | 63.77 | **63.716** |
| **ElGamal** | 3072-bit | 194.80 | 194.72 | 194.31 | 194.24 | 194.06 | **194.426** |

---

### 3. Tabel Detail: Transmission Delay (Latensi Komunikasi)

#### A. Menggunakan Fungsi Hash: SHA-256
| ![Transmission Delay Grouped SHA-256](assets/Transmission%20Delay%20SHA-256.jpeg) |

| Skema | Ukuran Kunci / Kurva | 50 Bytes | 100 Bytes | 150 Bytes | 200 Bytes | 250 Bytes | Rata-Rata |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **ECDSA** | secp192r1 | 0.27 | 0.20 | 0.28 | 0.25 | 0.27 | **0.254** |
| **ECDSA** | secp256r1 | 0.21 | 0.21 | 0.20 | 0.17 | 0.17 | **0.192** |
| **ECDSA** | secp384r1 | 0.55 | 0.56 | 0.55 | 0.59 | 0.58 | **0.566** |
| **ElGamal** | 1024-bit | 6.86 | 6.87 | 6.87 | 6.87 | 6.86 | **6.866** |
| **ElGamal** | 2048-bit | 43.78 | 43.79 | 43.78 | 43.78 | 43.95 | **43.816** |
| **ElGamal** | 3072-bit | 134.71 | 134.65 | 134.87 | 135.08 | 134.91 | **134.844** |

#### B. Menggunakan Fungsi Hash: SHA-384
| ![Transmission Delay Grouped SHA-384](assets/Transmission%20Delay%20SHA-384.jpeg) |

| Skema | Ukuran Kunci / Kurva | 50 Bytes | 100 Bytes | 150 Bytes | 200 Bytes | 250 Bytes | Rata-Rata |
| --- | --- | --- | --- | --- | --- | --- | --- |
| **ECDSA** | secp192r1 | 0.29 | 0.33 | 0.25 | 0.28 | 0.27 | **0.284** |
| **ECDSA** | secp256r1 | 0.21 | 0.17 | 0.19 | 0.19 | 0.18 | **0.188** |
| **ECDSA** | secp384r1 | 0.58 | 0.61 | 0.56 | 0.56 | 0.56 | **0.574** |
| **ElGamal** | 1024-bit | 7.19 | 7.24 | 7.19 | 7.18 | 7.20 | **7.200** |
| **ElGamal** | 2048-bit | 45.06 | 44.89 | 45.01 | 45.03 | 45.03 | **45.044** |
| **ElGamal** | 3072-bit | 137.20 | 137.10 | 136.98 | 137.83 | 137.52 | **137.326** |

---

## 📌 Kesimpulan Utama (Takeaways)

1. **Keunggulan Mutlak ECDSA:** Dalam hal waktu pemrosesan komputasi maupun pemanfaatan bandwidth komunikasi, ECDSA jauh mengungguli ElGamal. Struktur matematika kurva eliptik memungkinkannya menawarkan perlindungan setara dengan ukuran bit parameter yang jauh lebih ringkas.
2. **Standardisasi Mengalahkan Ukuran Kunci Pokok:** Pemanfaatan kurva terstandardisasi industri seperti `secp256r1` sangat direkomendasikan karena telah memiliki optimalisasi mendalam di level instruksi bahasa tingkat rendah (*assembly*) pustaka kriptografi native.
3. **Ukuran Dokumen Tidak Berdampak Sistematis:** Untuk dokumen berskala kecil-menengah (bytes hingga kilobytes), variasi ukuran berkas tidak memengaruhi delay komputasi maupun komunikasi, karena kalkulasi matematika tanda tangan selalu bekerja pada nilai ringkasan hash yang bersifat *fixed-length*.

---

## 🚀 Cara Menjalankan Kode Program

### 1. Instalasi Prasyarat

Pastikan pustaka kriptografi python standar sudah terpasang:

```bash
pip install cryptography

```

### 2. Eksekusi Pengujian Komputasi Lokal (Mandiri)

Jalankan skrip pengujian komputasi untuk mengekspor data statistik murni:

```bash
python benchmark_computation.py

```

Hasil pengujian komputasi murni akan tersimpan otomatis di berkas `results/computational_delay.csv`.

### 3. Eksekusi Jaringan Terdistribusi (Klien - Server)

* Di sisi **VM Server (172.20.0.103)**, aktifkan server pendengar:
```bash
python server.py

```


* Di sisi **VM Klien (172.20.0.106)**, jalankan pemancar paket payload:
```bash
python client.py

```



Seluruh data pencatatan *transmission delay* jaringan dan log verifikasi server akan otomatis tersimpan dalam direktori lokal `results/`.
