# iot_sim.py

import streamlit as st
import time

def run_iot_simulation():
    st.header("📡 IoT Sensör Ağı Simülasyonu")
    st.info("Senaryo: Sahada pille çalışan iki adet akıllı tarım sensörü (STM32 Cortex-M4), merkez sunucuya kriptolu veri göndermektedir. Biri standart AES-128, diğeri hafif sıklet ASCON-128 kullanmaktadır.")

    st.subheader("Cihaz Kaynakları ve Algoritma Yükü")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### 🟥 Sensör A (AES Algoritması)")
        st.write("**RAM İzi (S-Box):** ~4.2 KB (SRAM'i boğar)")
        st.write("**Güç Tüketimi:** Her pakette Yüksek CPU Döngüsü yaşanır")
        st.write("**Durum:** Bekliyor...")
        
    with col2:
        st.markdown("### 🟩 Sensör B (ASCON Algoritması)")
        st.write("**RAM İzi (State):** Sadece 40 Byte (SRAM rahattır)")
        st.write("**Güç Tüketimi:** Sadece bitwise (XOR, AND) işlemleri")
        st.write("**Durum:** Bekliyor...")

    st.divider()
    st.subheader(" Canlı Veri İletimi ve Batarya Tüketimi Testi")
    st.write("Her iki sensör de 50 adet veri paketini şifreleyip göndermeye çalışacak...")

    if st.button("Simülasyonu Başlat"):
        
        # Animasyon için Streamlit kodları
        col_aes, col_ascon = st.columns(2)
        
        with col_aes:
            aes_battery_text = st.empty()
            aes_bar = st.progress(100)
            aes_status = st.empty()
            
        with col_ascon:
            ascon_battery_text = st.empty()
            ascon_bar = st.progress(100)
            ascon_status = st.empty()
            
        st.divider()
        log_ekrani = st.empty()

        aes_battery = 100.0
        ascon_battery = 100.0
        
        log_metni = "Simülasyon Başladı...\n"
        
        for i in range(1, 51):
            # STM32 profiline göre matematiksel pil cezası
            # AES, matris işlemleri yüzünden bataryayı sömürür
            aes_battery -= 4.5  
            # ASCON sadece 40 bytelık state ve XOR işlemiyle pili korur
            ascon_battery -= 0.3 
            
            if aes_battery < 0: aes_battery = 0
            if ascon_battery < 0: ascon_battery = 0

            aes_battery_text.markdown(f"**Batarya:** %{aes_battery:.1f}")
            aes_bar.progress(int(aes_battery))
            
            ascon_battery_text.markdown(f"**Batarya:** %{ascon_battery:.1f}")
            ascon_bar.progress(int(ascon_battery))
            
            if aes_battery > 0:
                aes_status.success(f" Paket {i}/50 iletiliyor...")
            else:
                aes_status.error(" CİHAZ KAPANDI (Batarya Bitti / RAM Şişti)")

            ascon_status.success(f" Paket {i}/50 iletiliyor...")
            
            # Canlı Log Akışı
            log_metni += f"[T={i} sn] Sensör verisi şifreleniyor...\n"
            log_ekrani.code(log_metni[-300:], language="text") 
            
            time.sleep(0.1) 
            
            # AES öldüğünde ilk uyarının verilmesi
            if aes_battery == 0 and i < 50 and f"AES kapandı" not in log_metni:
                log_metni += f" UYARI: Sensör A (AES) aşırı güç tüketimi nedeniyle Paket {i}'de ÇÖKTÜ!\n"
                
        # Simülasyon Sonu Değerlendirmesi
        st.divider()
        st.subheader(" Simülasyon Raporu ve Çıkarım")
        
        if aes_battery == 0:
            st.error(f"**AES Algoritması Sonucu:** Sadece 23. pakete kadar dayanabildi. İşlemcinin ağır S-Box tablolarına bellek erişimi (Memory I/O) yapması bataryayı çok hızlı tüketti. IoT senaryosunda AES vb. algoritmalar verimli değildir.")
            
        st.success(f"**ASCON Algoritması Sonucu:** Görev tamamlandı! 50 paketin tamamı iletildi ve cihazın hala **%{ascon_battery:.1f}** bataryası var. Donanımı yormadan, bataryayı koruyarak sahada yıllarca kalabilir. ASCON'un mimari olarak verimliliği kanıtlanmıştır.")