import streamlit as st
import ascon_logic as ascon
import time
from Crypto.Cipher import AES
import pandas as pd
import benchmark
import kriptanaliz
import iot_sim


st.set_page_config(page_title="ASCON-128", page_icon="🛡️", layout="wide")


if 'original_cipher' not in st.session_state:
    st.session_state.original_cipher = None
if 'original_msg' not in st.session_state:
    st.session_state.original_msg = ""

st.title("🛡️ ASCON-128 ile Güvenli Veri İletimi ve Analizi")
st.markdown("---")


st.sidebar.header("İşlemler")
app_mode = st.sidebar.selectbox("İşlem Seçin:", ["Veri Şifreleme", "Gelişmiş Analiz","Resim-PDF Şifreleme","Akademik Kriptanaliz","IoT Simülasyonu"])

st.sidebar.divider()

st.sidebar.header(" Güvenlik Parametreleri")
key_input = st.sidebar.text_input("Gizli Anahtar (16 Karakter)", "Anahtar123456789", max_chars=16)
nonce_input = st.sidebar.text_input("Nonce (16 Karakter)", "Noncedegeri12345", max_chars=16)


if app_mode == "Veri Şifreleme":
    
    col1, col2 = st.columns([1.2, 0.8])

    with col1:
        st.subheader("1️ - Veriyi Şifrele ve AES ile Kıyasla")
        msg_input = st.text_area("Şifrelenecek Mesaj:", "", height=100)
        
        if st.button(" Şifreleme ve Performans Ölçme"):
            k = key_input.encode('utf-8')
            n = nonce_input.encode('utf-8')
            m = msg_input.encode('utf-8')
            
            t1 = time.perf_counter()
            cipher = ascon.ascon_encrypt(k, n, b"", m)
            ascon_time = (time.perf_counter() - t1) * 1000
            
            st.session_state.original_cipher = cipher
            st.session_state.original_msg = msg_input
            
            
            t3 = time.perf_counter()
            AES.new(k, AES.MODE_GCM, nonce=n[:12]).encrypt_and_digest(m)
            aes_time = (time.perf_counter() - t3) * 1000
            
            st.success("**ASCON Şifreli Metin (Hex):**")
            st.code(cipher.hex(), language="text")
            
            df = pd.DataFrame({"Algoritma": ["ASCON-128", "AES-128 (GCM)"], "Süre (ms)": [ascon_time, aes_time]})
            st.bar_chart(df.set_index("Algoritma"))

        if st.session_state.original_cipher:
            st.divider()
            st.subheader("2- (Çığ Etkisi) Analizi")
            st.info("Aşağıdaki kutuda metnin sadece 1 harfini değiştirin ve 'Farkı Gör' butonuna basın.")
            
            mod_msg_input = st.text_area("Değiştirilmiş Mesaj:", st.session_state.original_msg, height=100)
            
            if st.button(" Farkı Gör "):
                k = key_input.encode('utf-8')
                n = nonce_input.encode('utf-8')
                m_mod = mod_msg_input.encode('utf-8')
                
                new_cipher = ascon.ascon_encrypt(k, n, b"", m_mod)
                c1 = st.session_state.original_cipher
                c2 = new_cipher
                
                diff_bits = bin(int.from_bytes(c1, 'big') ^ int.from_bytes(c2, 'big')).count('1')
                total_bits = len(c1) * 8
                avalanche = (diff_bits / total_bits) * 100 if total_bits > 0 else 0
                
                col_c1, col_c2 = st.columns(2)
                col_c1.write("**Orijinal Şifre:**")
                col_c1.code(c1.hex())
                col_c2.write("**Yeni Şifre:**")
                col_c2.code(c2.hex())
                
                st.metric("Değişim Oranı", f"%{avalanche:.2f}")

    with col2:
        st.subheader(" Deşifreleme ")
        c_hex = st.text_area("Çözülecek Hex Kodunu Buraya Yapıştırın:", height=100)
        
        if st.button(" Metni Geri Çöz"):
            k = key_input.encode('utf-8')
            n = nonce_input.encode('utf-8')
            
            try:
                clean_hex = c_hex.strip().replace(" ", "").replace("\n", "")
                
                if len(clean_hex) == 0:
                    st.warning("Lütfen kutuya bir Hex kodu yapıştırın.")
                else:
                    c_bytes = bytes.fromhex(clean_hex)
                    dec = ascon.ascon_decrypt(k, n, b"", c_bytes)
                    
                    st.success("**Orijinal Metin:**")
                    st.markdown(f"### {dec.decode('utf-8', errors='ignore')}")
                    
            except ValueError as ve:
                st.error(f"Format Hatası: Girdiğiniz metin geçerli bir Hex değil. (Detay: {ve})")
            except Exception as e:
                st.error(f"Sistem Hatası: Şifre çözülemedi. (Detay: {e})")


elif app_mode == "Gelişmiş Analiz":
    benchmark.run_benchmark_panel(key_input, nonce_input)

elif app_mode == "Resim-PDF Şifreleme":
    st.header(" Dosya Şifreleme (Resim-PDF vb.)")
    st.info("Bu sayfada resim/pdf ve benzeri dosyalarımızı byte seviyesinde ASCON ile şifreleyebiliyoruz")

    col1, col2 = st.columns(2)

    with col1:
        st.subheader(" Dosya Şifrele")
        uploaded_file = st.file_uploader("Şifrelenecek dosyayı yükle", type=["png", "jpg", "jpeg", "pdf", "txt"])

        if uploaded_file is not None:
            if st.button("Dosyayı Şifrele"):
                k = key_input.encode('utf-8')
                n = nonce_input.encode('utf-8')

                file_bytes = uploaded_file.read()

                with st.spinner("Şifreleniyor.."):
                    cipher_bytes = ascon.ascon_encrypt(k, n, b"", file_bytes)

                st.success("Şifreleme Başarılı")
                
                st.download_button(
                    label=" Şifreli dosyayı indir (.enc)",
                    data=cipher_bytes,
                    file_name=uploaded_file.name + ".enc",
                    mime="application/octet-stream" 
                )

    with col2:
        st.subheader(" Dosya Çöz ")
        uploaded_enc_file = st.file_uploader("Şifreli dosyayı yükle (.enc)", type=["enc"])

        if uploaded_enc_file is not None:
            if st.button(" Dosyayı Çöz"):
                k = key_input.encode('utf-8')
                n = nonce_input.encode('utf-8')

                enc_bytes = uploaded_enc_file.read()

                with st.spinner("Şifre çözülüyor.."):
                    try:
                        dec_bytes = ascon.ascon_decrypt(k, n, b"", enc_bytes)
                        st.success(" Şifre başarıyla çözüldü")

                        original_name = uploaded_enc_file.name.replace(".enc", "")

                        st.download_button(
                            label=" Orjinal dosyayı indir",
                            data=dec_bytes,
                            file_name=original_name,
                            mime="application/octet-stream"
                        )
                    except Exception as e:
                        st.error("Hata! Yanlış anahtar veya bozuk dosya.")

elif app_mode == "Akademik Kriptanaliz":
    kriptanaliz.run_cryptanalysis_panel(key_input, nonce_input)

elif app_mode == "IoT Simülasyonu":
    iot_sim.run_iot_simulation()