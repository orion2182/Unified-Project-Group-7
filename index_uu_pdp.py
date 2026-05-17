import os
from langchain_community.document_loaders import PyPDFLoader
from langchain_text_splitters import RecursiveCharacterTextSplitter
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_chroma import Chroma

# --- CONFIGURATION ---
PDF_PATH = "UU Nomor 27 Tahun 2022.pdf"
PERSIST_DIRECTORY = "./db_uu_pdp"

def main():
    print("==============================================")
    print("   RAG Indexer - UU PDP No. 27 Tahun 2022")
    print("==============================================")

    if not os.path.exists(PDF_PATH):
        print(f"[!] Error: File '{PDF_PATH}' tidak ditemukan di direktori saat ini.")
        print("[!] Pastikan file PDF berada di folder yang sama dengan skrip ini.")
        return

    # 1. Load PDF
    print(f"[*] Membaca dokumen: {PDF_PATH}...")
    loader = PyPDFLoader(PDF_PATH)
    try:
        documents = loader.load()
        print(f"[+] Berhasil memuat {len(documents)} halaman.")
    except Exception as e:
        print(f"[!] Gagal membaca PDF: {e}")
        return

    # 2. Text Splitting (Chunking)
    print("[*] Memecah dokumen menjadi chunks (Semantic Splitting)...")
    text_splitter = RecursiveCharacterTextSplitter(
        chunk_size=600, 
        chunk_overlap=100,
        separators=["\nPasal", "\nBAB", "\n\n", "\n", " "]
    )
    chunks = text_splitter.split_documents(documents)
    print(f"[+] Berhasil membuat {len(chunks)} chunks.")

    # 3. Embedding Initialization
    print("[*] Menginisialisasi model embedding 'paraphrase-multilingual-MiniLM-L12-v2'...")
    try:
        embeddings = HuggingFaceEmbeddings(
            model_name="paraphrase-multilingual-MiniLM-L12-v2"
        )
    except Exception as e:
        print(f"[!] Gagal memuat model embedding: {e}")
        return

    # 4. ChromaDB Storage
    print(f"[*] Menyimpan vektor ke ChromaDB di direktori '{PERSIST_DIRECTORY}'...")
    try:
        vector_db = Chroma.from_documents(
            documents=chunks,
            embedding=embeddings,
            persist_directory=PERSIST_DIRECTORY
        )
        print("\n[V] PROSES INDEXING SELESAI!")
        print("[V] Database RAG siap digunakan oleh Agent Orchestrator.")
    except Exception as e:
        print(f"[!] Gagal menyimpan ke ChromaDB: {e}")

if __name__ == "__main__":
    main()
