
def ror(val, r):
    """64 bit sağa kaydırma """
    return ((val >> r) | (val << (64 - r))) & 0xFFFFFFFFFFFFFFFF

def ascon_permutation(state, rounds):
    """ 320-bit state karıştırma fonksiyonu"""
    constants = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87, 0x78, 0x69, 0x5a, 0x4b]
    start_idx = 12 - rounds

    for i in range(start_idx, 12):
        # 1. Sabit Ekleme kısmı
        state[2] ^= constants[i]

        # 2. S-Box katmanı
        state[0] ^= state[4]
        state[4] ^= state[3]
        state[2] ^= state[1]
        t0 = state[0] ^ (~state[1] & state[2]) & 0xFFFFFFFFFFFFFFFF
        t1 = state[1] ^ (~state[2] & state[3]) & 0xFFFFFFFFFFFFFFFF
        t2 = state[2] ^ (~state[3] & state[4]) & 0xFFFFFFFFFFFFFFFF
        t3 = state[3] ^ (~state[4] & state[0]) & 0xFFFFFFFFFFFFFFFF
        t4 = state[4] ^ (~state[0] & state[1]) & 0xFFFFFFFFFFFFFFFF
        
        state[0] = t0 ^ t4
        state[1] = t1 ^ t0
        state[2] = ~t2 & 0xFFFFFFFFFFFFFFFF
        state[3] = t3 ^ t2
        state[4] = t4 ^ t3

        # 3. Lineer Difüzyon katmanı
        state[0] ^= ror(state[0], 19) ^ ror(state[0], 28)
        state[1] ^= ror(state[1], 61) ^ ror(state[1], 39)
        state[2] ^= ror(state[2], 1) ^ ror(state[2], 6)
        state[3] ^= ror(state[3], 10) ^ ror(state[3], 17)
        state[4] ^= ror(state[4], 7) ^ ror(state[4], 41)

def ascon_initialize(key, nonce):
    IV = 0x80400c0600000000 # ASCON-128 Başlangıç Vektörü
    state = [
        IV,
        int.from_bytes(key[0:8], 'big'),
        int.from_bytes(key[8:16], 'big'),
        int.from_bytes(nonce[0:8], 'big'),
        int.from_bytes(nonce[8:16], 'big')
    ]
    ascon_permutation(state, 12)
    state[3] ^= int.from_bytes(key[0:8], 'big')
    state[4] ^= int.from_bytes(key[8:16], 'big')
    return state

def ascon_encrypt(key, nonce, associateddata, plaintext):
    """Metni ASCON-128 ile şifreler """
    state = ascon_initialize(key, nonce)
    
    if len(associateddata) > 0:
        state[0] ^= int.from_bytes(associateddata + b"\x80" + b"\x00" * (7 - len(associateddata) % 8), 'big')
        ascon_permutation(state, 6)
    state[4] ^= 1

    ciphertext = b""
    
    for i in range(0, len(plaintext) - (len(plaintext) % 8), 8):
        state[0] ^= int.from_bytes(plaintext[i:i+8], 'big')
        ciphertext += state[0].to_bytes(8, 'big')
        ascon_permutation(state, 6)
        
    last_len = len(plaintext) % 8
    last_pt = plaintext[len(plaintext) - last_len:] 
    padded_last_pt = last_pt + b"\x80" + b"\x00" * (7 - last_len)
    state[0] ^= int.from_bytes(padded_last_pt, 'big')
    
    ciphertext += state[0].to_bytes(8, 'big')[:last_len]
    
    return ciphertext

def ascon_decrypt(key, nonce, associateddata, ciphertext):
    """Şifreli ASCON-128 metnini orijinal haline döndürür """
    state = ascon_initialize(key, nonce)
    
    if len(associateddata) > 0:
        state[0] ^= int.from_bytes(associateddata + b"\x80" + b"\x00" * (7 - len(associateddata) % 8), 'big')
        ascon_permutation(state, 6)
    state[4] ^= 1

    plaintext = b""
    
    for i in range(0, len(ciphertext) - (len(ciphertext) % 8), 8):
        c_block = int.from_bytes(ciphertext[i:i+8], 'big')
        plaintext += (state[0] ^ c_block).to_bytes(8, 'big')
        state[0] = c_block
        ascon_permutation(state, 6)
        
    last_len = len(ciphertext) % 8
    last_ct = ciphertext[len(ciphertext) - last_len:] 
    
    c_last_padded = int.from_bytes(last_ct + b"\x00" * (8 - last_len), 'big')
    p_last = (state[0] ^ c_last_padded) >> (64 - 8 * last_len)
    plaintext += p_last.to_bytes(last_len, 'big')
    
   
    state[0] ^= (p_last << (64 - 8 * last_len)) | (0x80 << (64 - 8 * last_len - 8))
    
    return plaintext