# 🛡️ Dokumentasi Teknis: Unified-Shield AI Agent (Kelompok 7)
**Project Title:** AI-Driven Penetration Testing & UU PDP Compliance Integration
**Date:** Saturday, May 16, 2026

---

## 1. Pendahuluan & Objektif
Dokumentasi ini merangkum pengembangan sistem **Autonomous Pentest Agent** yang dirancang untuk memenuhi kriteria Capstone Project Cybersecurity 2026. Fokus utama adalah integrasi antara keamanan ofensif (Pentesting) dengan kepatuhan hukum (Compliance) menggunakan teknologi AI.

### Core Objectives:
1. **Otomasi Pentest:** Melakukan deteksi kerentanan kritis (fokus: BOLA API).
2. **Legal Mapping (RAG):** Menghubungkan temuan teknis ke UU No. 27 Tahun 2022 (UU PDP).
3. **Sinergi Defensif:** Menghasilkan output yang dapat digunakan oleh tim SIEM (Wazuh) dan Threat Hunting.

---

## 2. Arsitektur Komponen

### A. Knowledge Layer (RAG System)
- **Engine:** index_uu_pdp.py
- **Embedding Model:** paraphrase-multilingual-MiniLM-L12-v2
- **Vector Database:** ChromaDB.
- **Proses:** Dokumen PDF UU PDP dipecah menjadi 170 chunks dengan separator berbasis Pasal dan BAB.

### B. Offensive Layer (AI Skills)
- **Engine:** skills/api_pentest.md
- **Focus:** Broken Object Level Authorization (BOLA).
- **Teknik Lanjut:** Parameter Pollution, Array Wrapping, WAF Evasion.

### C. Compliance Layer (Auditor Skills)
- **Engine:** skills/pdp_compliance_auditor.md
- **Logic:** Memetakan kategori serangan ke pasal-pasal spesifik (Pasal 35, 38, 39, 46).

---

## 3. Alur Kerja Sistem (Workflow)

1. **Indexing:** AI membaca PDF UU PDP -> Chunking -> Simpan ke Vector DB.
2. **Discovery:** AI Agent mengeksekusi alat pentest terhadap endpoint target.
3. **Semantic Query:** Temuan teknis dikirim ke modul RAG untuk mencari dasar hukum.
4. **Synthesis:** AI menyusun laporan yang menggabungkan bukti teknis dengan analisis sanksi hukum.
5. **Defense Integration:** AI menghasilkan Sigma Rule untuk deteksi SIEM.

---

## 4. Hasil Eksekusi & Bukti (Deliverables)

### Temuan Teknis Utama:
- **Vulnerability:** Broken Object Level Authorization (BOLA).
- **Target:** https://api.bank-pdp.local/v1/nasabah/profile/1005
- **Evidence:** Penyerang berhasil mengakses data nasabah menggunakan teknik Parameter Pollution.

### Dasar Hukum yang Dilanggar:
- **Pasal 38:** Kewajiban Pengendali Data Pribadi melindungi Data Pribadi dari pemrosesan yang tidak sah.
- **Pasal 39:** Kewajiban mencegah akses tidak sah terhadap Data Pribadi.

---

## 5. Strategi Memenuhi Rubrik (Level 4)

| Kriteria | Status | Bukti Implementasi |
| :--- | :--- | :--- |
| **Integrasi Sistem** | OK | Output Pentest diintegrasikan dengan analisis hukum dan deteksi SIEM. |
| **Ketajaman Teknis** | OK | Penggunaan teknik mutasi lanjut (Parameter Pollution). |
| **Analisis UU PDP** | OK | Penggunaan RAG memastikan kutipan pasal hukum akurat. |
| **Otomasi** | OK | Seluruh proses berjalan secara otonom. |

---

## 6. Lokasi File Proyek
Semua file tersimpan di: /home/vedara/Documents/Kelompok 7/

---
**Status Dokumentasi:** Final & Complete
