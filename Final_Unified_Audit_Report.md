# 🛡️ UNIFIED AUDIT REPORT: Project Shield-PDP
**Kelompok 7 | Grey Box Pentest & Compliance Audit**

## 1. Technical Attack Surface

### A. Vulnerability: Broken Object Level Authorization (BOLA)
- **Target:** https://api.bank-pdp.local/v1/nasabah/profile/1005
- **Severity:** 9.8 (Critical)
- **Description:** Penyerang berhasil membocorkan JWT Admin dan melakukan Lateral Movement.
- **Impact:** Enkripsi database (Simulasi Ransomware).

### B. Vulnerability: Improper Input Validation (Real-World Evidence)
- **Target:** answer-inbox-bacon-fibre.trycloudflare.com
- **Endpoint:** /api/v1/audits/my-login-logs/
- **Severity:** 4.3 (Medium)
- **Description:** Parameter 'limit' tidak divalidasi. Input negatif/non-integer mengembalikan SEMUA records.
- **Impact:** Information Disclosure (Pajanan seluruh log login).

## 2. UU PDP No. 27/2022 Compliance Mapping

### Pasal 35 (Kewajiban Keamanan Teknis)
> *"Pengendali Data Pribadi wajib melindungi Data Pribadi dari pemrosesan yang tidak sah dengan melakukan langkah teknis keamanan."*
- **Audit:** Kegagalan validasi input pada parameter 'limit' membuktikan kurangnya langkah teknis keamanan yang memadai.

### Pasal 39 (Pencegahan Akses Tidak Sah)
> *"Pengendali Data Pribadi wajib mencegah Data Pribadi diakses secara tidak sah."*
- **Audit:** Temuan BOLA dan Input Validation memungkinkan pihak yang tidak berhak mengakses data pribadi dalam skala besar.

## 3. Business Impact & Sanctions
- **Denda Administratif:** Pasal 57 mencatat denda hingga 2% dari total pendapatan tahunan.
- **Reputasi:** Kebocoran log login dapat menurunkan kepercayaan nasabah terhadap sistem perbankan.

## 4. Remediation Roadmap
1. **Immediate:** Terapkan sanitasi input integer pada semua parameter API.
2. **Immediate:** Perbaiki otorisasi level objek (BOLA) menggunakan JWT Claims.
3. **Mid-term:** Implementasikan Enkripsi at Rest (Pasal 35).