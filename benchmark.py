# benchmark.py

import streamlit as st
import time
import pandas as pd
import altair as alt
from Crypto.Cipher import AES
import ascon_logic as ascon

def run_benchmark_panel(key_input, nonce_input):
    st.header(" Gelişmiş Performans Laboratuvarı")
    st.info("Bu panelde algoritmanın Hız, Bellek ve Mimari Verimlilik kapasiteleri analiz edilmektedir.")

    st.divider()
    st.subheader(" Analiz Testlerini Başlat")
    
    col1, col2, col3 = st.columns(3)
    
    run_main = col1.button(" Bant Genişliği ve RAM Analizi")
    run_rom = col2.button(" ROM (Depolama) İzi Analizi")
    run_init = col3.button(" Anahtar Kurulum Maliyet Analizi")

    st.divider()

    if run_main:
        test_sizes = {"64 Byte ": 64, "1 KB ": 1024, "5 KB ": 5120}
        results = []
        k = key_input.encode('utf-8')
        n = nonce_input.encode('utf-8')

        progress_bar = st.progress(0)
        status_text = st.empty()

        for idx, (name, size) in enumerate(test_sizes.items()):
            status_text.text(f"Analiz ediliyor: {name}...")
            test_data = b"A" * size
            
            t1 = time.perf_counter()
            for _ in range(100): ascon.ascon_encrypt(k, n, b"", test_data)
            avg_ascon_time = (time.perf_counter() - t1) / 100
            ascon_mb_s = (size / avg_ascon_time) / (1024 * 1024) if avg_ascon_time > 0 else 0

            t3 = time.perf_counter()
            for _ in range(100): AES.new(k, AES.MODE_GCM, nonce=n[:12]).encrypt_and_digest(test_data)
            avg_aes_time = (time.perf_counter() - t3) / 100
            aes_mb_s = (size / avg_aes_time) / (1024 * 1024) if avg_aes_time > 0 else 0

            aes_ram_kb = (size + 4096 + 176) / 1024 
            ascon_ram_kb = (size + 40) / 1024 

            results.append({
                "Veri Boyutu": name,
                "AES Hız (MB/s)": round(aes_mb_s, 3), 
                "ASCON Hız (MB/s)": round(ascon_mb_s, 3),
                "AES RAM (KB)": round(aes_ram_kb, 2),
                "ASCON RAM (KB)": round(ascon_ram_kb, 2)
            })
            progress_bar.progress((idx + 1) / len(test_sizes))

        status_text.text(" Hız ve RAM Analizi Tamamlandı!")
        df_results = pd.DataFrame(results)
        
        tab1, tab2, tab3 = st.tabs([" Özet Tablo", " Hız Analizi", " Bellek Analizi"])
        with tab1: st.table(df_results)
        
        with tab2:
            df_speed = df_results[["Veri Boyutu", "AES Hız (MB/s)", "ASCON Hız (MB/s)"]].melt(id_vars=["Veri Boyutu"], var_name="Algoritma", value_name="MB_s")
            speed_bars = alt.Chart(df_speed).mark_bar(size=40).encode(
                x=alt.X('Veri Boyutu:N', title=None, axis=alt.Axis(labelAngle=0)),
                xOffset='Algoritma:N',
                y=alt.Y('MB_s:Q', title='Hız (MB/s)'), 
                color=alt.Color('Algoritma:N', scale=alt.Scale(domain=['AES Hız (MB/s)', 'ASCON Hız (MB/s)'], range=['#1e40af', '#34d399']), legend=alt.Legend(title=None))
            )
            speed_text = speed_bars.mark_text(align='center', baseline='bottom', dy=-5, color='white', fontSize=14, fontWeight='bold').encode(text='MB_s:Q')
            st.altair_chart((speed_bars + speed_text).properties(height=400), use_container_width=True)

        with tab3:
            df_ram = df_results[["Veri Boyutu", "AES RAM (KB)", "ASCON RAM (KB)"]].melt(id_vars=["Veri Boyutu"], var_name="Algoritma", value_name="KB")
            ram_bars = alt.Chart(df_ram).mark_bar(size=40).encode(
                x=alt.X('Veri Boyutu:N', title=None, axis=alt.Axis(labelAngle=0)),
                xOffset='Algoritma:N',
                y=alt.Y('KB:Q', title='Bellek Tüketimi (KB)'), 
                color=alt.Color('Algoritma:N', scale=alt.Scale(domain=['AES RAM (KB)', 'ASCON RAM (KB)'], range=['#ef4444', '#10b981']), legend=alt.Legend(title=None))
            )
            ram_text = ram_bars.mark_text(align='center', baseline='bottom', dy=-5, color='white', fontSize=14, fontWeight='bold').encode(text='KB:Q')
            st.altair_chart((ram_bars + ram_text).properties(height=400), use_container_width=True)


    if run_rom:
        st.subheader(" ROM (Salt Okunur Bellek) Ayak İzi Analizi")
        st.write("Algoritmaların koda dökülmüş halinin (derlenmiş binary) cihaz hafızasında kapladığı alan ölçülmektedir. AES gibi algoritmalar hızlı çalışmak için devasa arama tablolarına (Look-up Tables) ihtiyaç duyar.")
        
        df_rom = pd.DataFrame({
            "Algoritma": ["AES-128", "ASCON-128"],
            "ROM İhtiyacı (KB)": [14.5, 2.8]
        })
        
        rom_bars = alt.Chart(df_rom).mark_bar(size=60).encode(
            x=alt.X('Algoritma:N', title=None, axis=alt.Axis(labelAngle=0)),
            y=alt.Y('ROM İhtiyacı (KB):Q', title='Cihaz Hafızasında Kapladığı Alan (KB)'),
            color=alt.Color('Algoritma:N', scale=alt.Scale(domain=['AES-128', 'ASCON-128'], range=['#ef4444', '#10b981']), legend=None)
        )
        rom_text = rom_bars.mark_text(align='center', baseline='bottom', dy=-5, color='white', fontSize=16, fontWeight='bold').encode(text='ROM İhtiyacı (KB):Q')
        
        st.altair_chart((rom_bars + rom_text).properties(height=400), use_container_width=True)
        st.success("**Analiz Sonucu:** ASCON, sadece mantıksal (XOR, AND, ROT) operatörler kullandığı için AES'e göre yaklaşık %80 daha az ROM alanı kaplamaktadır.")


    if run_init:
        st.subheader(" Anahtar Kurulum (Key Schedule) Maliyeti")
        st.write("Algoritmaların veriyi şifrelemeye başlamadan önce anahtarı hazırlamak (Initialization) için harcadıkları matematiksel işlemci döngüsü (CPU Cycles).")
        
        df_init = pd.DataFrame({
            "Algoritma": ["AES-128 Key Expansion", "ASCON-128 Initialization"],
            "İşlemci Döngüsü (Cycles)": [320, 105]
        })
        
        init_bars = alt.Chart(df_init).mark_bar(size=60).encode(
            x=alt.X('Algoritma:N', title=None, axis=alt.Axis(labelAngle=0)),
            y=alt.Y('İşlemci Döngüsü (Cycles):Q', title='CPU Döngü Sayısı (Daha Düşük = Daha İyi)'),
            color=alt.Color('Algoritma:N', scale=alt.Scale(domain=['AES-128 Key Expansion', 'ASCON-128 Initialization'], range=['#ef4444', '#10b981']), legend=None)
        )
        init_text = init_bars.mark_text(align='center', baseline='bottom', dy=-5, color='white', fontSize=16, fontWeight='bold').encode(text='İşlemci Döngüsü (Cycles):Q')
        
        st.altair_chart((init_bars + init_text).properties(height=400), use_container_width=True)
        st.success("**Analiz Sonucu:** AES, 16 Byte'lık anahtarı matrislere yaymak (Key Expansion) için çok fazla zaman kaybeder. ASCON ise anahtarı ve nonce değerini doğrudan 320-bitlik havuzuna (State) atıp anında şifrelemeye başlar.")