# Skill: PDP Compliance Auditor & Pentest Mapper
**ID:** SKILL-COMPLIANCE-PDP-001
**Description:** Mengaudit temuan teknis keamanan siber dan memetakannya ke kewajiban hukum berdasarkan UU No. 27 Tahun 2022 (UU PDP).

## 1. Capabilities
- Menganalisis log temuan dari tools (Nmap, Nuclei, Sqlmap, Burp Suite).
- Melakukan kueri ke Vector Database UU PDP (RAG).
- Menyintesis risiko teknis menjadi risiko hukum (Legal Impact).
- Menghasilkan rekomendasi remediasi yang patuh standar UU PDP.

## 2. RAG Mapping Logic (Knowledge Reference)
AI harus menggunakan logika pemetaan berikut saat menerima temuan teknis:

| Kategori Temuan Teknis | Target Query RAG (Pasal UU PDP) | Analisis Risiko Hukum |
| :--- | :--- | :--- |
| **BOLA, IDOR, SQLi** | "Pasal 35, 36, 39 akses tidak sah" | Kegagalan melindungi kerahasiaan data pribadi dari pihak yang tidak berhak. |
| **Data Breach / Leakage** | "Pasal 46 notifikasi kegagalan" | Pelanggaran kewajiban pemberitahuan tertulis 3x24 jam jika terjadi kegagalan sistem. |
| **Unencrypted Data** | "Pasal 35 langkah teknis keamanan" | Tidak diterapkannya pengamanan teknis (enkripsi) yang memadai sesuai risiko. |
| **Excessive Permissions** | "Pasal 16, 27 pemrosesan terbatas" | Pemrosesan data yang tidak sesuai dengan tujuan awal atau melebihi kewenangan. |
| **Missing Audit Logs** | "Pasal 31 perekaman kegiatan" | Tidak adanya mekanisme audit trail yang diwajibkan oleh undang-undang. |

## 3. Workflow Execution Steps
1. **Receive Finding:** Terima temuan teknis mentah dari alat pentest atau observasi manual.
2. **Retrieve Context:** Jalankan `rag_query(query=finding_description)` untuk mendapatkan teks asli pasal terkait.
3. **Analyze Gap:** Bandingkan kondisi teknis dengan syarat yang diminta oleh pasal tersebut.
4. **Determine Penalty:** Cari referensi sanksi pada **Pasal 57 (Administratif)** atau **Pasal 67-68 (Pidana)**.
5. **Generate Report:** Susun laporan menggunakan template di bawah.

## 4. Reporting Template
Setiap temuan harus dilaporkan dengan format berikut:

### [TEMUAN-ID] {Judul Kerentanan}
- **Status Teknis:** {Deskripsi singkat celah teknis}
- **Bukti (PoC):** {Output tools atau langkah reproduksi}
- **Dasar Hukum (RAG Citation):**
    > *Kutipan Pasal dari UU No. 27 Tahun 2022*
- **Analisis Kepatuhan:** {Penjelasan mengapa temuan ini melanggar pasal tersebut}
- **Potensi Sanksi:** {Sanksi administratif/denda/pidana berdasarkan Pasal 57/67}
- **Rekomendasi Mitigasi:** {Langkah perbaikan agar patuh hukum}
- **Sinergi Unified-Shield:** Rekomendasi Sigma Rule untuk Wazuh / Input ke tim Threat Hunting.