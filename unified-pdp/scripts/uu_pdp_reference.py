#!/usr/bin/env python3
"""UU PDP Detailed Reference — Full article explanations for capstone reports.

Provides detailed explanations of UU No. 27 Tahun 2022 articles
for inclusion in PoC reports and compliance documentation.
"""

UU_PDP_ARTICLES = {
    "Pasal 16": {
        "title": "Tujuan Pemrosesan Data Pribadi",
        "content": "Pemrosesan Data Pribadi harus dilakukan untuk tujuan yang spesifik, sah, dan dinyatakan secara jelas. Data Pribadi yang telah dikumpulkan tidak boleh diproses untuk tujuan lain yang tidak sesuai dengan tujuan awal tanpa persetujuan baru dari Subjek Data Pribadi.",
        "relevance": "Pelanggaran terjadi ketika penyerang mengumpulkan atau memproses data pribadi untuk tujuan yang tidak sah (misalnya: eksfiltrasi data, credential harvesting).",
        "sanksi": "Pasal 57 (sanksi administratif), Pasal 67-68 (sanksi pidana)"
    },
    "Pasal 20": {
        "title": "Keamanan Data Pribadi",
        "content": "Pengendali Data Pribadi wajib melindungi dan mengamankan Data Pribadi dari kehilangan, penyalahgunaan, akses tidak sah, dan kebocoran data. Perlindungan ini mencakup langkah-langkah teknis dan organisasional yang memadai.",
        "relevance": "Pelanggaran terjadi ketika sistem tidak memiliki proteksi yang memadai terhadap scanning, enumeration, atau akses tidak sah.",
        "sanksi": "Pasal 57 (sanksi administratif), Pasal 67-68 (sanksi pidana)"
    },
    "Pasal 23": {
        "title": "Persetujuan Subjek Data Pribadi",
        "content": "Pemrosesan Data Pribadi memerlukan persetujuan yang sah dari Subjek Data Pribadi. Persetujuan harus diberikan secara tertulis atau elektronik, dengan pemahaman yang jelas tentang tujuan pemrosesan.",
        "relevance": "Pelanggaran terjadi ketika penyerang menggunakan kredensial valid (T1078) untuk mengakses data tanpa persetujuan pemilik data.",
        "sanksi": "Pasal 57, Pasal 65-68"
    },
    "Pasal 25": {
        "title": "Kewajiban Pengendali Data Pribadi",
        "content": "Pengendali Data Pribadi wajib menunjukkan bukti bahwa pemrosesan Data Pribadi telah dilakukan dengan persetujuan yang sah dari Subjek Data Pribadi.",
        "relevance": "Pelanggaran terjadi ketika kredensial disimpan tidak aman (T1552) dan tidak ada bukti persetujuan pemrosesan.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 27": {
        "title": "Hak Subjek Data Pribadi",
        "content": "Subjek Data Pribadi berhak mendapatkan akses, perbaikan, dan penghapusan Data Pribadi mereka. Pengendali Data Pribadi harus memfasilitasi penggunaan hak-hak ini.",
        "relevance": "Pelanggaran terjadi ketika data pribadi dikumpulkan tanpa pengetahuan subjek data (misalnya: keylogging, screen capture).",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 28": {
        "title": "Pemrosesan Data Terbatas",
        "content": "Pemrosesan Data Pribadi hanya boleh dilakukan untuk tujuan yang telah dinyatakan dan tidak boleh melampaui batas tujuan tersebut. Pengendali Data Pribadi harus memastikan bahwa pemrosesan dilakukan secara proporsional.",
        "relevance": "Pelanggaran terjadi ketika penyerang memanipulasi akun (T1098) atau menemukan permission groups (T1069) untuk memperluas akses di luar batas yang diizinkan.",
        "sanksi": "Pasal 57, Pasal 65-68"
    },
    "Pasal 29": {
        "title": "Akurasi Data Pribadi",
        "content": "Pengendali Data Pribadi wajib memastikan bahwa Data Pribadi yang diproses adalah akurat, lengkap, dan tidak menyesatkan. Data harus diperbarui sesuai kebutuhan.",
        "relevance": "Pelanggaran terjadi ketika penyerang memalsukan atau memanipulasi data pribadi (T1565) untuk keuntungan tidak sah.",
        "sanksi": "Pasal 57, Pasal 66-68"
    },
    "Pasal 30": {
        "title": "Penghentian Pemrosesan Data Tidak Akurat",
        "content": "Pengendali Data Pribadi wajib menghentikan pemrosesan Data Pribadi yang tidak akurat atau telah kedaluwarsa, dan mengambil langkah korektif yang diperlukan.",
        "relevance": "Pelanggaran terjadi ketika data yang sudah tidak akurat tetap diproses atau ketika penyerang menggunakan data lama untuk akses tidak sah.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 31": {
        "title": "Perekaman Kegiatan Pemrosesan Data",
        "content": "Pengendali Data Pribadi wajib melakukan perekaman kegiatan pemrosesan Data Pribadi. Rekaman ini harus mencakup jenis data, tujuan pemrosesan, pihak yang terlibat, dan periode penyimpanan.",
        "relevance": "Pelanggaran terjadi ketika penyerang menghapus log sistem (T1070) atau meng impair defenses (T1562) untuk menghindari deteksi dan audit trail.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 32": {
        "title": "Hak Akses Subjek Data",
        "content": "Subjek Data Pribadi berhak memperoleh konfirmasi apakah Data Pribadi mereka sedang diproses, dan jika ya, berhak mengakses data tersebut serta informasi terkait pemrosesannya.",
        "relevance": "Pelanggaran terjadi ketika penyerang melakukan account discovery (T1087) untuk menemukan akun dan data pengguna tanpa otorisasi.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 33": {
        "title": "Penghapusan Indikator Kompromi",
        "content": "Pengendali Data Pribadi wajib menjaga integritas catatan pemrosesan data dan tidak boleh menghapus atau mengubah catatan tersebut tanpa alasan yang sah.",
        "relevance": "Pelanggaran terjadi ketika penyerang menghapus indikator kompromi (T1070) yang menghambat audit trail dan investigasi insiden.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 34": {
        "title": "Notifikasi Pelanggaran Data",
        "content": "Pengendali Data Pribadi wajib memberitahukan kepada Lembaga dan Subjek Data Pribadi dalam waktu paling lambat 3x24 jam apabila terjadi Kegagalan Pelindungan Data Pribadi.",
        "relevance": "Pelanggaran terjadi ketika sistem tidak memiliki mekanisme notifikasi yang memadai untuk mendeteksi dan melaporkan active scanning (T1595) atau vulnerability scanning.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 35": {
        "title": "Langkah Teknis Keamanan Data",
        "content": "Pengendali Data Pribadi wajib melakukan langkah-langkah teknis dan organisasional untuk melindungi Data Pribadi, termasuk enkripsi, pseudonimisasi, dan langkah-langkah keamanan lainnya yang memadai.",
        "relevance": "Pelanggaran terjadi ketika sistem tidak memiliki proteksi teknis yang memadai terhadap eksploitasi (T1190), command execution (T1059), atau privilege escalation (T1068).",
        "sanksi": "Pasal 57 (sanksi administratif), Pasal 67-68 (sanksi pidana)"
    },
    "Pasal 36": {
        "title": "Langkah Teknis Operasional",
        "content": "Pengendali Data Pribadi wajib menerapkan langkah-langkah teknis operasional yang mencakup pengelolaan akses, pencatatan kegiatan, dan pemantauan keamanan secara berkala.",
        "relevance": "Pelanggaran terjadi ketika tidak ada pengelolaan akses yang memadai, memungkinkan penyerang melakukan brute force (T1110) atau credential stuffing (T1110.004).",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 37": {
        "title": "Keamanan Sistem Elektronik",
        "content": "Pengendali Data Pribadi wajib memastikan bahwa sistem elektronik yang digunakan untuk memproses Data Pribadi memiliki tingkat keamanan yang memadai dan sesuai dengan perkembangan teknologi.",
        "relevance": "Pelanggaran terjadi ketika sistem elektronik tidak diamankan dengan baik, memungkinkan obfuscation (T1027) atau indicator removal (T1070) untuk menghindari deteksi.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 38": {
        "title": "Perlindungan dari Pemrosesan Tidak Sah",
        "content": "Data Pribadi wajib dilindungi dari pemrosesan yang tidak sah, termasuk akses, pengumpulan, penggunaan, pengungkapan, atau penghapusan tanpa otorisasi yang sah.",
        "relevance": "Pelanggaran terjadi ketika penyerang melakukan lateral movement (T1210), remote services exploitation (T1021), atau exfiltration (T1567) untuk mengakses data tanpa otorisasi.",
        "sanksi": "Pasal 57, Pasal 65-68"
    },
    "Pasal 39": {
        "title": "Pencegahan Akses Tidak Sah",
        "content": "Pengendali Data Pribadi wajib mencegah akses tidak sah terhadap Data Pribadi melalui implementasi kontrol akses yang ketat, autentikasi multi-faktor, dan pemantauan akses secara berkala.",
        "relevance": "Pelanggaran terjadi ketika penyerang menggunakan valid accounts (T1078), session cookie theft (T1539), atau token manipulation (T1134) untuk akses tidak sah.",
        "sanksi": "Pasal 57, Pasal 65-68"
    },
    "Pasal 40": {
        "title": "Penghentian Pemrosesan Data",
        "content": "Pengendali Data Pribadi wajib menghentikan pemrosesan Data Pribadi apabila tujuan pemrosesan telah tercapai, Subjek Data Pribadi menarik persetujuan, atau terdapat permintaan penghapusan dari Subjek Data Pribadi.",
        "relevance": "Pelanggaran terjadi ketika data destruction (T1485) dilakukan setelah penarikan persetujuan, atau ketika account access removal (T1531) menghambat penghentian pemrosesan.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 41": {
        "title": "Penundaan dan Pembatasan Pemrosesan",
        "content": "Subjek Data Pribadi berhak meminta penundaan atau pembatasan pemrosesan Data Pribadi mereka dalam kondisi tertentu, dan Pengendali Data Pribadi wajib mematuhi permintaan tersebut.",
        "relevance": "Pelanggaran terjadi ketika endpoint denial of service (T1499) atau system shutdown (T1529) mengganggu kemampuan penghentian pemrosesan data.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 42": {
        "title": "Pengakhiran Pemrosesan Data Pribadi",
        "content": "Pengendali Data Pribadi wajib mengakhiri pemrosesan Data Pribadi apabila terdapat perintah dari Lembaga, putusan pengadilan, atau alasan hukum lainnya yang mengharuskan penghentian.",
        "relevance": "Pelanggaran terjadi ketika system shutdown (T1529) atau data destruction (T1485) dilakukan secara tidak sah, mengganggu pengakhiran pemrosesan yang seharusnya.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 43": {
        "title": "Pemusnahan Data Pribadi",
        "content": "Pengendali Data Pribadi wajib memusnahkan Data Pribadi yang telah melampaui periode penyimpanan atau tidak lagi diperlukan untuk tujuan pemrosesan, kecuali terdapat ketentuan hukum yang menyatakan sebaliknya.",
        "relevance": "Pelanggaran terjadi ketika unauthorized data destruction (T1561) dilakukan tanpa mengikuti prosedur pemusnahan yang sah.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 44": {
        "title": "Kewajiban Memusnahkan Data Pribadi",
        "content": "Pengendali Data Pribadi wajib memusnahkan Data Pribadi secara aman dan tidak dapat dipulihkan kembali, dengan menggunakan metode yang sesuai standar keamanan yang berlaku.",
        "relevance": "Pelanggaran terjadi ketika data destruction (T1485) dilakukan secara tidak sah atau ketika data tidak dimusnahkan sesuai kewajiban hukum.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 45": {
        "title": "Notifikasi Kegagalan Pelindungan Data",
        "content": "Pengendali Data Pribadi wajib memberitahukan Kegagalan Pelindungan Data Pribadi kepada Lembaga dan Subjek Data Pribadi dalam waktu paling lambat 3x24 jam sejak kegagalan diketahui.",
        "relevance": "Pelanggaran terjadi ketika exfiltration (T1567) terjadi dan tidak ada mekanisme notifikasi yang memadai untuk mendeteksi dan melaporkan kegagalan perlindungan.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 46": {
        "title": "Notifikasi Kegagalan kepada Subjek Data",
        "content": "Pengendali Data Pribadi wajib memberitahukan Kegagalan Pelindungan Data Pribadi kepada Subjek Data Pribadi apabila kegagalan tersebut berpotensi menimbulkan risiko tinggi terhadap hak dan kebebasan Subjek Data Pribadi.",
        "relevance": "Pelanggaran terjadi ketika data encrypted for impact (T1486) atau exfiltration (T1567, T1041, T1048) terjadi dan tidak ada notifikasi kepada subjek data.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 47": {
        "title": "Audit Keamanan Data",
        "content": "Pengendali Data Pribadi wajib melakukan audit keamanan Data Pribadi secara berkala untuk memastikan bahwa langkah-langkah keamanan yang diterapkan masih efektif dan sesuai dengan perkembangan ancaman.",
        "relevance": "Pelanggaran terjadi ketika indicator removal (T1070) atau impair defenses (T1562) menghambat kemampuan audit keamanan data.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 48": {
        "title": "Evaluasi Dampak Pelindungan Data",
        "content": "Pengendali Data Pribadi wajib melakukan evaluasi dampak Pelindungan Data Pribadi apabila pemrosesan Data Pribadi memiliki risiko tinggi terhadap hak dan kebebasan Subjek Data Pribadi.",
        "relevance": "Pelanggaran terjadi ketika data encrypted for impact (T1486) atau defacement (T1491) terjadi tanpa evaluasi dampak sebelumnya.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 49": {
        "title": "Penghapusan Indikator Kompromi",
        "content": "Pengendali Data Pribadi wajib menjaga integritas sistem dan catatan keamanan, serta tidak boleh menghapus atau mengubah indikator kompromi tanpa alasan yang sah dan terdokumentasi.",
        "relevance": "Pelanggaran terjadi ketika indicator removal (T1070) atau impair defenses (T1562) dilakukan untuk menghindari deteksi dan investigasi.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 50": {
        "title": "Kewajiban Pelaporan Insiden",
        "content": "Pengendali Data Pribadi wajib melaporkan insiden keamanan Data Pribadi kepada Lembaga dalam waktu yang ditentukan, dengan menyertakan informasi lengkap mengenai jenis insiden, dampak, dan langkah penanggulangan.",
        "relevance": "Pelanggaran terjadi ketika endpoint denial of service (T1499) atau insiden keamanan lainnya tidak dilaporkan sesuai kewajiban.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 51": {
        "title": "Pengendali dan Prosesor Data Pribadi",
        "content": "Pengendali Data Pribadi wajib memastikan bahwa Proesor Data Pribadi yang digunakan memiliki langkah-langkah keamanan yang memadai dan mematuhi ketentuan perlindungan Data Pribadi.",
        "relevance": "Pelanggaran terjadi ketika external remote services (T1133) digunakan melalui prosesor yang tidak memenuhi standar keamanan.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 52": {
        "title": "Kewajiban Keamanan Kredensial",
        "content": "Pengendali Data Pribadi wajib mengamankan kredensial akses terhadap Data Pribadi dengan menggunakan metode enkripsi, penyimpanan yang aman, dan pengelolaan akses yang ketat.",
        "relevance": "Pelanggaran terjadi ketika unsecured credentials (T1552) ditemukan dalam file, registry, atau konfigurasi sistem tanpa proteksi yang memadai.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 53": {
        "title": "Pengawasan Keamanan Data",
        "content": "Pengendali Data Pribadi wajib melakukan pengawasan terhadap keamanan Data Pribadi secara berkelanjutan, termasuk pemantauan akses, deteksi anomali, dan respons insiden.",
        "relevance": "Pelanggaran terjadi ketika impair defenses (T1562) atau indicator removal (T1070) menghambat kemampuan pengawasan keamanan data.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 54": {
        "title": "Penghapusan Indikator Kompromi",
        "content": "Pengendali Data Pribadi wajib menjaga integritas catatan keamanan dan tidak boleh menghapus indikator kompromi yang dapat digunakan untuk investigasi insiden keamanan.",
        "relevance": "Pelanggaran terjadi ketika indicator removal (T1070) dilakukan untuk menghambat investigasi insiden keamanan data pribadi.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 55": {
        "title": "Transfer Data Pribadi",
        "content": "Transfer Data Pribadi ke luar wilayah Negara Kesatuan Republik Indonesia hanya dapat dilakukan apabila negara tujuan memiliki tingkat perlindungan Data Pribadi yang setara atau lebih tinggi, atau terdapat persetujuan dari Subjek Data Pribadi.",
        "relevance": "Pelanggaran terjadi ketika data exfiltration (T1567) atau transfer to cloud account (T1537) dilakukan ke luar negeri tanpa memenuhi persyaratan transfer data.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 56": {
        "title": "Transfer Data Lintas Batas",
        "content": "Pengendali Data Pribadi wajib memastikan bahwa transfer Data Pribadi lintas batas negara dilakukan dengan mekanisme yang sah dan memenuhi standar perlindungan yang berlaku.",
        "relevance": "Pelanggaran terjadi ketika cloud account abuse (T1078.004) atau data exfiltration (T1530, T1537) dilakukan ke luar negeri tanpa mekanisme yang sah.",
        "sanksi": "Pasal 57, Pasal 67-68"
    },
    "Pasal 57": {
        "title": "Sanksi Administratif",
        "content": "Pelanggaran terhadap ketentuan UU PDP dapat dikenakan sanksi administratif berupa: peringatan tertulis, denda administratif, penghentian pemrosesan Data Pribadi, penghapusan Data Pribadi, dan/atau pencabutan izin.",
        "relevance": "Sanksi ini berlaku untuk semua pelanggaran teknis yang ditemukan selama pengujian penetrasi, termasuk akses tidak sah, eksfiltrasi data, dan kegagalan perlindungan data.",
        "sanksi": "Denda administratif hingga 2% dari penghasilan tahunan, penghentian pemrosesan, pencabutan izin"
    },
    "Pasal 65": {
        "title": "Larangan Memperoleh Data Pribadi Bukan Miliknya",
        "content": "Setiap Orang dengan sengaja dan tanpa hak memperoleh Data Pribadi yang bukan miliknya dengan maksud untuk menguntungkan diri sendiri atau orang lain yang dapat merugikan Subjek Data Pribadi.",
        "relevance": "Pelanggaran terjadi ketika penyerang menggunakan valid accounts (T1078), credential access (T1003), atau data collection (T1005, T1213) untuk memperoleh data pribadi bukan miliknya.",
        "sanksi": "Pidana penjara paling lama 5 tahun dan/atau denda paling banyak Rp5.000.000.000"
    },
    "Pasal 66": {
        "title": "Larangan Membuat Data Pribadi Palsu",
        "content": "Setiap Orang dengan sengaja dan tanpa hak membuat Data Pribadi palsu dengan maksud menguntungkan diri sendiri atau orang lain yang dapat merugikan Subjek Data Pribadi.",
        "relevance": "Pelanggaran terjadi ketika penyerang memalsukan data pribadi (T1565) untuk keuntungan tidak sah atau untuk merugikan subjek data.",
        "sanksi": "Pidana penjara paling lama 5 tahun dan/atau denda paling banyak Rp5.000.000.000"
    },
    "Pasal 67": {
        "title": "Pidana untuk Pelanggaran Keamanan Data",
        "content": "Setiap Orang dengan sengaja dan tanpa hak mengungkapkan Data Pribadi yang bukan miliknya dipidana dengan pidana penjara paling lama 4 tahun dan/atau denda paling banyak Rp4.000.000.000.",
        "relevance": "Pelanggaran terjadi ketika data exfiltration (T1567, T1041, T1048) atau data disclosure terjadi tanpa otorisasi yang sah.",
        "sanksi": "Pidana penjara paling lama 4 tahun dan/atau denda paling banyak Rp4.000.000.000"
    },
    "Pasal 68": {
        "title": "Pidana untuk Pelanggaran Privasi",
        "content": "Setiap Orang dengan sengaja dan tanpa hak menggunakan Data Pribadi yang bukan miliknya dipidana dengan pidana penjara paling lama 4 tahun dan/atau denda paling banyak Rp4.000.000.000.",
        "relevance": "Pelanggaran terjadi ketika penyerang menggunakan data pribadi yang diperoleh secara tidak sah untuk keuntungan pribadi atau merugikan subjek data.",
        "sanksi": "Pidana penjara paling lama 4 tahun dan/atau denda paling banyak Rp4.000.000.000"
    },
    "Pasal 69": {
        "title": "Pidana untuk Pelanggaran Data untuk Impact",
        "content": "Setiap Orang dengan sengaja dan tanpa hak merusak atau menghancurkan Data Pribadi yang bukan miliknya dipidana dengan pidana penjara paling lama 6 tahun dan/atau denda paling banyak Rp6.000.000.000.",
        "relevance": "Pelanggaran terjadi ketika data encrypted for impact (T1486) atau data destruction (T1485) dilakukan terhadap data pribadi bukan miliknya.",
        "sanksi": "Pidana penjara paling lama 6 tahun dan/atau denda paling banyak Rp6.000.000.000"
    },
    "Pasal 71": {
        "title": "Pidana untuk Pelanggaran Berat",
        "content": "Pelanggaran tertentu terhadap UU PDP yang mengakibatkan kerugian besar bagi Subjek Data Pribadi dapat dikenakan pidana penjara paling lama 6 tahun dan/atau denda paling banyak Rp6.000.000.000.",
        "relevance": "Pelanggaran berat termasuk ransomware (T1486), data destruction (T1485), dan exfiltration data skala besar (T1567).",
        "sanksi": "Pidana penjara paling lama 6 tahun dan/atau denda paling banyak Rp6.000.000.000"
    },
    "Pasal 73": {
        "title": "Pidana Tambahan",
        "content": "Selain pidana pokok, terdapat pidana tambahan berupa pencabutan izin usaha, pembubaran badan hukum, dan/atau perampasan barang yang digunakan untuk melakukan pelanggaran.",
        "relevance": "Pidana tambahan dapat diterapkan untuk pelanggaran berat yang melibatkan penggunaan sistem atau infrastruktur untuk melakukan serangan.",
        "sanksi": "Pencabutan izin usaha, pembubaran badan hukum, perampasan barang"
    },
}


def get_article_detail(pasal: str) -> dict:
    """Get detailed information about a UU PDP article."""
    return UU_PDP_ARTICLES.get(pasal, {
        "title": "Unknown",
        "content": "Article not found in database",
        "relevance": "N/A",
        "sanksi": "N/A"
    })


def get_articles_for_technique(technique_id: str) -> list:
    """Get UU PDP articles relevant to a MITRE ATT&CK technique."""
    import sys
    from pathlib import Path
    # Add the parent directory (Kelompok 7) which contains scripts/
    project_root = Path(__file__).parent.parent.parent
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    from scripts.mitre_attack_mapper import MITRE_UU_PDP_MAP

    mapping = MITRE_UU_PDP_MAP.get(technique_id, {})
    pasal_list = mapping.get("pasal", [])

    articles = []
    for pasal in pasal_list:
        detail = get_article_detail(pasal)
        articles.append({
            "pasal": pasal,
            "title": detail["title"],
            "content": detail["content"],
            "relevance": detail["relevance"],
            "sanksi": detail["sanksi"],
        })

    return articles


def format_articles_for_report(technique_id: str) -> str:
    """Format UU PDP articles for inclusion in PoC report."""
    articles = get_articles_for_technique(technique_id)

    if not articles:
        return "No UU PDP articles mapped for this technique."

    output = "## Analisis Kepatuhan UU PDP (UU No. 27 Tahun 2022)\n\n"
    output += f"**MITRE ATT&CK Technique:** {technique_id}\n\n"

    for article in articles:
        output += f"### {article['pasal']}: {article['title']}\n\n"
        output += f"**Isi Pasal:**\n{article['content']}\n\n"
        output += f"**Relevansi dengan Temuan:**\n{article['relevance']}\n\n"
        output += f"**Potensi Sanksi:**\n{article['sanksi']}\n\n"
        output += "---\n\n"

    return output


if __name__ == "__main__":
    # Test
    print("Testing UU PDP Detailed Reference:")
    print(format_articles_for_report("T1078"))
