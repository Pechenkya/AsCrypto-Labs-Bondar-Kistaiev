# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %% [markdown]
# # Лабораторна робота 1 з "Асиметричних криптосистем та протоколів"
# ## Тема: Побудова тестів для перевірки якості випадкових та псевдовипадкових послідовностей.
# 
# **Виконали**\
# Бондар Петро, ФІ-03\
# Кістаєв Матвій, ФІ-03
# %% [markdown]
# ## Підготовка до виконання лабораторнох роботи

# %%
import numpy as np
import random
import secrets
import io
import scipy

N = 1000000
Alpha = 0.05

# %% [markdown]
# ## Функція статистичних тестів

# %%
# Швидко не буде.
def bits_to_bytes(seq):
    n = len(seq) // 8
    res = np.zeros(n ,dtype=np.uint8)

    bit_string = "".join(map(str, list(seq)))
    res = np.array([int("0b" + bit_string[i*8:(i*8)+8], 2) for i in range(n)])

    return res


# %%
def test(seq: np.array, b = 8):
    n = len(seq)

    # Рівномірність
    counts = np.zeros(2**b)
    n_j = n / (2**b)

    for a in seq:
        counts[a] += 1

    stat_U = np.sum((counts - n_j)**2 / n_j)
    quant_U = scipy.stats.chi2.ppf(1 - Alpha, 2**b - 1)
    
    print("Тест на рівноймовірність символів:  " + str(stat_U <= quant_U) + "   (" + str(stat_U) + ")")


    # Незалежність символів
    pair_counts = np.zeros((2**b, 2**b), dtype=float)

    for i in range(0, n-1, 1):
        pair_counts[seq[i]][seq[i+1]] = pair_counts[seq[i]][seq[i+1]] + 1

    S = 0
    for i in range(0, 2**b):
        for j in range(0, 2**b):
            d = (np.sum(pair_counts[i, :]) * np.sum(pair_counts[:, j]))
            if d != 0:
                S += (pair_counts[i, j] ** 2) / d

    stat_I = n * (S - 1)
    quant_I = scipy.stats.chi2.ppf(1 - Alpha, (2**b - 1)**2)

    print("Тест на незалежність символів:  " + str(stat_I <= quant_I) + "   (" + str(stat_I) + ")")

    # Однорідність послідовності
    r = 200
    interval_counts = np.zeros((r, 2**b), dtype=float)

    for i in range(0, r):
        for j in range(0, n // r):
            c = seq[r*i + j]
            interval_counts[i, c] += 1

    S = 0
    for i in range(0, r):
        for j in range(0, 2**b):
            d = (np.sum(interval_counts[i, :]) * np.sum(interval_counts[:, j]))
            if d != 0:
                S += (interval_counts[i, j] ** 2) / d
    
    stat_H = n * (S - 1)
    quant_H = scipy.stats.chi2.ppf(1 - Alpha, (2**b - 1) * (r - 1))

    print("Тест на однорідність послідовності:  " + str(stat_H <= quant_H) + "   (" + str(stat_H) + ")")

# %% [markdown]
# ## Генератори і результати їх тестування
# %% [markdown]
# ### Вбудовані генератори
# %% [markdown]
# #### Криптографічно нестійкий генератор

# %%
print("\nВбудований генератор, нестійкий криптографічно (bits):")
unsafe_bits_seq = np.array([random.randint(0, 1) for _ in range(N)], dtype=np.uint8)
test(bits_to_bytes((unsafe_bits_seq)))

print("\nВбудований генератор, нестійкий криптографічно (bytes):")
unsafe_bytes_seq = np.array(list(random.randbytes(N)), dtype=np.uint8)
test(unsafe_bytes_seq)

# %% [markdown]
# #### Криптографічно стійкий генератор

# %%
print("\nВбудований генератор, стійкий криптографічно (bits):")
safe_bits_seq = np.array([secrets.randbelow(2) for _ in range(N)], dtype=np.uint8)
test(safe_bits_seq, 1)

print("\nВбудований генератор, стійкий криптографічно (bytes):")
safe_bytes_seq = np.array(list(secrets.token_bytes(N)), dtype=np.uint8)
test(safe_bytes_seq)

# %% [markdown]
# ### Генератор Лемера

# %%
class Linear_Low:
    a = 2**16 + 1
    c = 119
    x0 = 5  # тюряга #

    def generate_bytes(self, n: int):
        seq = np.zeros(n, dtype=np.uint32)
        seq[0] = self.x0

        for i in range(0, n - 1):
            seq[i+1] = (self.a*seq[i] + self.c) 

        seq = np.array(seq % (2**8), dtype=np.uint8)

        return seq

class Linear_High:
    a = 2**16 + 1
    c = 119
    x0 = 1  # тюряга #

    def generate_bytes(self, n: int):
        seq = np.zeros(n, dtype=np.uint32)
        seq[0] = self.x0

        for i in range(0, n - 1):
            seq[i+1] = (self.a*seq[i] + self.c)

        seq = np.array(seq >> 24, dtype=np.uint8)

        return seq


# %%
de1 = Linear_Low()
de2 = Linear_High()

t1 = de1.generate_bytes(N)
t2 = de2.generate_bytes(N)

print("\nГенератор Лемера (Low):")
test(t1)
print()
print("\nГенератор Лемера (High):")
test(t2)

# %% [markdown]
# ### Генератор L20

# %%
class L20:
    def __init__(self, x_init: np.array):
        self.x_init = x_init

    def generate_bits(self, n: int):
        seq = np.concatenate([np.array(self.x_init, dtype=np.uint8), np.zeros(n - 20, dtype=np.uint8)])

        for i in range(20, n):
            seq[i] = seq[i - 3] ^ seq[i - 5] ^ seq[i - 9] ^ seq[i - 20]

        return seq
            


# %%
smp = np.array([random.randint(0, 1) for _ in range(20)])

de_L20 = L20(smp)

print("\nГенератор L20 (1M bits):")
print(f"Початкове заповнення: {smp}")
test(bits_to_bytes(de_L20.generate_bits(N)))


print("\nГенератор L20 (16M bits):")
test(bits_to_bytes(de_L20.generate_bits(16*N)))

# %% [markdown]
# ### Генератор L89

# %%
class L89:
    def __init__(self, x_init: np.array):
        self.x_init = x_init

    def generate_bits(self, n: int):
        seq = np.concatenate([np.array(self.x_init, dtype=np.uint8), np.zeros(n - 89, dtype=np.uint8)])

        for i in range(89, n):
            seq[i] = seq[i - 38] ^ seq[i - 89]

        return seq
            


# %%
smp = np.array([random.randint(0, 1) for _ in range(89)])
de_L89 = L89(smp)

print("\nГенератор L89 (1M bits):")
print(f"Початкове заповнення: {smp}")
test(bits_to_bytes(de_L89.generate_bits(N)))

# %% [markdown]
# ### Генератор Джиффі

# %%
class Geffe:
    def __init__(self, x_init: np.array, y_init: np.array, s_init: np.array):
        self.x = x_init # 11 bits, x11 = x0 + x2
        self.y = y_init # 9 bits,  y9 = y0 + y1 + y3 + y4
        self.s = s_init # 10 bits, s10 = s0 + s3

    def generate_bits(self, n: int):
        seq = np.zeros(n, dtype=np.uint8)

        for i in range(0, n):
            seq[i] = (self.s[0] * self.x[0]) ^ ((1 ^ self.s[0]) * self.y[0])
            # Linear Shift
            self.x[0] = self.x[0] ^ self.x[2]
            self.x = np.roll(self.x, -1)
            self.y[0] = self.y[0] ^ self.y[1] ^ self.y[3] ^ self.y[4]
            self.y = np.roll(self.y, -1)
            self.s[0] = self.s[0] ^ self.s[3]
            self.s = np.roll(self.s, -1)

        return seq
            


# %%
x = np.array([random.randint(0, 1) for _ in range(11)])
y = np.array([random.randint(0, 1) for _ in range(9)])
s = np.array([random.randint(0, 1) for _ in range(10)])


Ge_generator = Geffe(x, y, s)

print("\nГенератор Джиффі:")
print(f"x = {x}")
print(f"y = {y}")
print(f"s = {s}")

test(bits_to_bytes(Ge_generator.generate_bits(N)))

# %% [markdown]
# ### Генератор "Бібліотекар"

# %%
class Librarian:
    def __init__(self, filename):
        file = io.open(filename, mode='r', encoding='utf-8')
        self.text = file.read()

    
    def generate_bytes(self, n: int):
        if len(self.text) < n:
            raise RuntimeError("Nema sliv, odni emotions")

        seq = np.zeros(n, dtype=np.uint8)

        for i in range(0, n):
            seq[i] = (ord(self.text[i]) % 2**8)

        return seq
            


# %%
de_Lb = Librarian("fanfiction.txt")

print("\nГенератор \"Бібліотекар\":")
test(de_Lb.generate_bytes(N))

# %% [markdown]
# ### Генератор Вольфрама

# %%
# В ПІТОНІ НЕМА ВБУДОВАНОГО ЦИКЛІЧНОГО ЗСУВУ
def rcs(n: np.uint32, rotations) -> np.uint32: 
    return (n >> rotations | n << (32-rotations)) % 2**32

def lcs(n: np.uint32, rotations) -> np.uint32:
    return (n << rotations | n >> (32-rotations)) % 2**32

class Wolfram:
    def __init__(self, r0: np.uint32):
        self.r0 = r0

    def generate_bits(self, n: int):
        r_i = self.r0
        seq = np.zeros(n, dtype=np.uint8)

        for i in range(0, n):
            seq[i] = r_i % 2
            r_i = lcs(r_i, 1) ^ (r_i | rcs(r_i, 1))

        return seq
            


# %%
de_wolfram = Wolfram(1)

print("\nГенератор Вольфрама:")
test(bits_to_bytes(de_wolfram.generate_bits(N)))

# %% [markdown]
# ### Генератор BM

# %%
class BM:
    def __init__(self, p, a):
        self.p = p
        self.a = a

    def generate_bits(self, n: int):
        seq = np.zeros(n, dtype=object)
        seq[0] = random.randint(0, self.p - 1) 

        for i in range(1, n):
            seq[i] = pow(self.a, seq[i - 1], self.p)

        seq = np.array(seq < (self.p - 1) / 2, dtype=np.uint8) 

        return seq
    
    def generate_bytes(self, n: int):
        seq = np.zeros(n, dtype=object)
        seq[0] = random.randint(0, self.p - 1) 

        for i in range(1, n):
            seq[i] = pow(self.a, seq[i - 1], self.p)

        seq = np.array((seq * 256) // (self.p - 1), dtype=np.uint8) 

        return seq
            


# %%
p = int("CEA42B987C44FA642D80AD9F51F10457690DEF10C83D0BC1BCEE12FC3B6093E3", 16)
a = int("5B88C41246790891C095E2878880342E88C79974303BD0400B090FE38A688356", 16)

de_BM = BM(p, a)

print("\nГенератор BM (bits):")
test(bits_to_bytes(de_BM.generate_bits(N)))

print("\nГенератор BM (bytes):")
test(de_BM.generate_bytes(N))

# %% [markdown]
# ### Генератор BBS

# %%
class BBS:
    def __init__(self, p, q):
        self.n = p*q

    def generate_bits(self, n: int):
        seq = np.zeros(n, dtype=object)
        seq[0] = random.randint(2, self.n - 1) 

        for i in range(1, n):
            seq[i] = pow(seq[i - 1], 2, self.n)

        seq = np.array(seq % 2, dtype=np.uint8) 

        return seq
    
    def generate_bytes(self, n: int):
        seq = np.zeros(n, dtype=object)
        seq[0] = random.randint(2, self.n - 1) 

        for i in range(1, n):
            seq[i] = pow(seq[i - 1], 2, self.n)

        seq = np.array(seq % (2**8), dtype=np.uint8) 

        return seq
            


# %%
p = int("D5BBB96D30086EC484EBA3D7F9CAEB07", 16)
q = int("425D2B9BFDB25B9CF6C416CC6E37B59C1F", 16)

de_BBS = BBS(p, q)

print("\nГенератор BSS (bits):")
test(bits_to_bytes(de_BBS.generate_bits(N)))

print("\nГенератор BSS (bytes):")
test(de_BBS.generate_bytes(N))
