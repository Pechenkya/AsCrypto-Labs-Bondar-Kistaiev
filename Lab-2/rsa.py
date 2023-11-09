# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %% [markdown]
# # Лабораторна робота 2 з "Асиметричних криптосистем та протоколів"
# ## Тема: Вивчення криптосистеми RSA та алгоритму електронного підпису
# 
# **Виконали**\
# Бондар Петро, ФІ-03\
# Кістаєв Матвій, ФІ-03

# %%
import numpy as np
import random
import math
import hashlib
import requests

# %% [markdown]
# ## Генератор простих чисел
# 
# Для генерації чисел ми використаємо генератор BBS з лабораторної роботи 1. 
# 
# Для узагальнення генерації ми зберігатимемо стан генератора, на якому зупинилась попередня послідовність. 

# %%
class BBS:
    def __init__(self, p, q, state = 0):
        self.n = p*q
        self.state = state

        if state == 0:
            self.state = random.randint(2, self.n - 1)
    
    def generate_bytes(self, n: int):
        seq = np.zeros(n, dtype=object)
        seq[0] = self.state

        for i in range(1, n):
            seq[i] = pow(seq[i - 1], 2, self.n)

        self.state = seq[-1]
        seq = np.array(seq % (2**8), dtype=np.uint8) 

        return seq
    
def bytes_to_num(byte_seq):
    res = 0
    for b in byte_seq:
        res = res*(2**8) + int(b)

    return res

# %% [markdown]
# Після чого, згенеровані числа заданої довжини будуть перевірятися на сильну простоту:
# 
# 1. Спочатку саме згенероване число $n$ перевіряється на простоту.
# 2. Після чого на простоту перевіряється число $\frac{n - 1}{2}$.
# 
# Для перевірки числа на простоту ми скористаємося комбінацією методу пробних ділень та алгоритмом Міллера-Рабіна.

# %%
OPTIMUS_PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 
                  61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 
                  137, 139, 149, 151, 157]
R = {}

for d in OPTIMUS_PRIMES:
    R[d] = [1]
    while R[d].count(R[d][-1]) < 2:
        R[d].append((R[d][-1] * 2) % d)
    R[d].pop()

# Метод пробних ділень
def petod_drobnyx_mylen(num):
    b = bin(num)[:1:-1]
    
    if b[0] == '0':
        return 2
    
    for d in OPTIMUS_PRIMES[1::]:
        sum = 0
        for i in range(len(b)):
            sum += int(b[i]) * R[d][i % len(R[d])]
            sum %= d
        
        if sum == 0:
            return d

    return 1
    
# Ймовірнісний алгоритм Міллера-Рабіна та загальний алгоритм для знаходження простих чисел
def miller_rabin(num, base):
    i = 1
    while (num - 1) % (2 ** i) == 0:
        i += 1

    k = i - 1
    d = (num - 1) // (2 ** k)

    a_d = pow(base, d, num)

    if a_d == 1:
        return True
    
    a_d2i = a_d
    for j in range(k):
        if a_d2i == (num - 1):
            return True
        
        a_d2i = (a_d2i ** 2) % num

    return False


def check_prime(num, error_prob = 0.001):
    if petod_drobnyx_mylen(num) != 1:
        return False

    t = int(math.ceil(math.log(1 / error_prob, 4)))
    s = 0
    for _ in range(t):
        a = random.randrange(3, num + 1)
        s += int(miller_rabin(num, a))

    return s > (t / 2)

# Генератор простих чисел
def generate_prime(len: int, excl = []):
    gen = BBS(int('425D2B9BFDB25B9CF6C416CC6E37B59C1F', 16), int('D5BBB96D30086EC484EBA3D7F9CAEB07', 16))

    while True:
        p = bytes_to_num(gen.generate_bytes(len // 8))
        if check_prime(p) and (p not in excl):
            return p

# Генератор сильнопростих чисел
def generate_safe_prime(len: int, excl = []):
    gen = BBS(int('425D2B9BFDB25B9CF6C416CC6E37B59C1F', 16), int('D5BBB96D30086EC484EBA3D7F9CAEB07', 16))

    while True:
        seq = gen.generate_bytes(len // 8)
        if seq[0] < 128:
            continue
        
        p = bytes_to_num(seq)
        if not check_prime(p) or (p in excl):
            continue

        q = (p - 1) // 2
        if check_prime(q):
            return p

# %% [markdown]
# ## Взаємодія з віддаленим сервером
# 
# У якості сервера з яким ми будемо спілкуватися ми скористалися **asymcryptwebservice**, який нам люб'язно надав Олег Миколайович.
# 
# Клас **Server** дозволяє налагодити сесію спілкування з сервісом та надає зручний інтерфейс для надсилання запитів, що необхідні для цієї лабораторної роботи.

# %%
KEY_LENGTH = 256


class Server:
    __base_url = 'http://asymcryptwebservice.appspot.com/rsa/'
    s = requests.Session()
    n = None
    e = None
    
    # Setup server private key and receive server pub key
    def set_server_key(self, key_l: int) -> (str, str):
        req = f'{self.__base_url}serverKey?keySize={key_l}'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        self.n, self.e = (int(r['modulus'], 16), int(r['publicExponent'], 16))
        return (self.n, self.e)
    
    # Ask server to encrypt
    def encrypt(self, M: str, rec_n, rec_e, type='TEXT'):
        req = f'{self.__base_url}encrypt?modulus={format(rec_n, "X")}&publicExponent={format(rec_e, "X")}&message={M}&type={type}'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        return r['cipherText']
    
    # Ask server to decrypt this message with his private keys
    def decrypt(self, C: str, type='TEXT'):
        req = f'{self.__base_url}decrypt?cipherText={C}&expectedType={type}'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        return r['message']
    
    # Ask server to sign this message with his private keys
    def sign(self, M: str, type='TEXT'):
        req = f'{self.__base_url}sign?message={M}&type={type}'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        return r['signature']
    
    # Verify the message using this public key
    def verify(self, M: str, sign: str, u_n, u_e, type='TEXT'):
        req = f'{self.__base_url}verify?message={M}&type={type}&signature={sign}&modulus={format(u_n, "X")}&publicExponent={format(u_e, "X")}'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        return r['verified']
    
    # Receive a pair (64bit encrypted key, signature for this key) from the server
    def sendKey(self, rec_n, rec_e) -> (str, str):
        req = f'{self.__base_url}sendKey?modulus={format(rec_n, "X")}&publicExponent={format(rec_e, "X")}'
        print(f"Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code} for request {req}")
        r = r.json()
        print(f"response: {r}")
        return (r["key"], r['signature'])
    
    # Ask server to decrypt and verify key encrypted with user's modulo and publicExponent
    def receiveKey(self, K_enc: str, sign, u_n, u_e):
        req = f'{self.__base_url}receiveKey?key={K_enc}&signature={sign}&modulus={format(u_n, "X")}&publicExponent={format(u_e, "X")}'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        return r['verified']

# %% [markdown]
# ## Опис процесу спілкування
# %% [markdown]
# ### Службові функції перетворення
# 
# Іноді дані необхідно відправити у певному форматі, а бо вони приходять у цьому форматі.
# 
# Для перетворення даних між різними формами довелося імплементувати методи **str2hex** та **num2str**.

# %%
def str2hex(s: str):
    res = ""

    for c in s:
        cb = hex(ord(c))
        res += cb[2::]

    return res

def num2str(n: int):
    text = str()
    while n != 0:
        text += chr(n % 256)
        n //= 256
    
    return text[::-1]

# %% [markdown]
# ### Абстракція користувача
# 
# Для спілкування необхідний абонент, що буде надсилати, отримувати та оброблювати запити від сервера. Для цього створений клас **User**:
# 
# 1. При ініціалізації він приймає значення **p** та **q**, що будуть його публічним ключем, а також опціонально публічну експоненту **e** та сервер. У випадку відсутності заданого сервера створиться новий об'єт та запуститься нова сесія спілкування з сервером. В будь-якому випадку, при створенні коритсувача будуть заново згенеровані публічний та особистий ключ на стороні сервера, що буде використовуватись під час взаємодіїю
# 2. Метод **send_message** дозволяє зашифрувати та надіслати повідомлення **M** серверу відповідно до протоколу спілкування. У відповідь користувач повинен розшифроване сервером повідомлення.
# 3. Метод **send_message_sign** дозволяє отримати підпис **S** для повідомлення **M** та надіслати цю пару серверу напряму для верифікації підпису.
# 4. Метод **receive_message** дозволяє надіслати серверу відкрито повідомлення **M** та отримати його у зашифрованому вигляді. 
# 5. Метод **receive_message_sign** дозволяє надіслати серверу відкрито повідомлення **M** та отримати відкрито підпис для цього повідомлення.
# 6. Метод **receive_secret_key** дозволяє надіслати серверу запит на отримання 64 бітного секретного ключа, зашифрованого та підписаного за допомогою параметрів взаємодії.
# 7. Метод **send_secret_key** дозволяє надіслати серверу секретний ключ, зашифрований та підписаний за допомогою параметрів взаємодії.
# 
# В кожному методі результати взаємодії перевіряються та результат перевірки надається користувачу.

# %%
class User:
    def __init__(self, p, q, e = 2**16 + 1, serv = Server()):
        print("Initializing user...")
        if not check_prime(p) or not check_prime(q):
            raise RuntimeError("p or q is not a prime number.")
        if math.gcd(e, (p-1)*(q-1)) != 1:
            raise RuntimeError("e is not invertible modulo phi(n)")
        
        self.serv = serv
        self.p = p
        self.q = q
        self.e = e
        self.n = p*q
        self.d = pow(e, -1, (self.p - 1)*(self.q - 1))
        self.get_server_public_key(KEY_LENGTH * 2)

        print(f"User private key (d, p, q): {(self.d, self.p, self.q)}")
        print(f"User public key (n, e): {(self.n, self.e)}")
        print(f"User server public key (n, e): {(self.serv.n, self.serv.e)}")
        print("--------------------------------------------------------")
    

    def get_server_public_key(self, len: int):
        self.serv.set_server_key(len)


    def send_message(self, M: str):
        print("Sending message to the server...")
        if int(str2hex(M), 16) > self.serv.n:
            raise RuntimeError("Cannot send the message. Its' length is larger than server's modulo.")

        C = format(pow(int(str2hex(M), 16), self.serv.e, self.serv.n), 'X')
        M1 = self.serv.decrypt(C)
        
        check = (M1 == M)

        print(f"Sent message: {M}")
        print(f"Sent cyphertext: {C}")
        print(f"Server responce: {M1}")
        
        if check:
            print("Success")
        else:
            print("Error")
        print("--------------------------------------------------------")


    def send_message_sign(self, M: str):
        print("Sending signature to the server...")
        
        S = format(pow(int(str2hex(M), 16), self.d, self.n), 'X')

        check = self.serv.verify(M, S, self.n, self.e)

        print(f"Sent message: {M}")
        print(f"Sent signature: {S}")
        
        if check:
            print("Success")
        else:
            print("Error")
        print("--------------------------------------------------------")
    

    def receive_message(self, M: str):
        print("Sending request for message to the server...")
        if self.n < int(str2hex(M), 16):
            raise RuntimeError("Cannot receive the message. User's modulo is smaller than message length")
        
        C = self.serv.encrypt(M, self.n, self.e)
        M1 = num2str(pow(int(C, 16), self.d, self.n))

        check = (M1 == M)

        print(f"Sent message: {M}")
        print(f"Received cyphertext: {C}")
        print(f"Decoded cyphertext: {M1}")
        
        if check:
            print("Success")
        else:
            print("Error")
        print("--------------------------------------------------------")
        
        
    def receive_message_sign(self, M: str):
        print("Sending request for message signature to the server...")
        
        S = self.serv.sign(M)
        M1 = num2str(pow(int(S, 16), self.serv.e, self.serv.n))
        
        check = (M1 == M)

        print(f"Sent message: {M}")
        print(f"Received signature: {S}")
        print(f"Message signed with signature: {M1}")
        
        if check:
            print("Success")
        else:
            print("Error")
        print("--------------------------------------------------------")
        
        
    def receive_secret_key(self):
        print("Sending request for signed secter key to the server...")
        if self.n < self.serv.n:
            raise RuntimeError("Cannot receive the key. User's modulo is smaller than server's.")
        
        s_K, s_S = self.serv.sendKey(self.n, self.e)
        K = pow(int(s_K, 16), self.d, self.n)
        S = pow(int(s_S, 16), self.d, self.n)

        check = (pow(S, self.serv.e, self.serv.n) == K)

        print(f"Received key (decoded): {format(K, 'X')}")
        print(f"Received signature (decoded): {format(S, 'X')}")
        
        print("Verification:")
        if check:
            print("\tSuccess")
        else:
            print("\tError")
        print("--------------------------------------------------------")
            
        

    def send_secret_key(self, K: str):
        print("Sending signed secter key to the server...")
        if self.n > self.serv.n:
            raise RuntimeError("Cannot send key. User's modulo is larger than server's.")
        if int(K, 16) > self.serv.n:
            raise RuntimeError("Cannot send the key. Key length is larger than server's modulo.")

        EK = pow(int(K, 16), self.serv.e, self.serv.n)
        ES = pow(pow(int(K, 16), self.d, self.n), self.serv.e, self.serv.n)

        check = self.serv.receiveKey(format(EK, "X"), format(ES, "X"), self.n, self.e)

        print(f"Sent key: {K}")
        print(f"Sent key (encoded): {format(EK, 'X')}")
        print(f"Sent signature (encoded): {format(ES, 'X')}")
        
        print("Verification:")
        if check:
            print("\tSuccess")
        else:
            print("\tError")
        print("--------------------------------------------------------")

# %% [markdown]
# ## Симуляція взаємодії
# %% [markdown]
# ### Створення параметрів для приватних ключів
# 
# За допомогою генератора сильнопростих чисел згенеруємо два коротких числа (для користувача 1) і два довгих числа (для користувача 2).

# %%
print(f"Довжина модуля сервера: {2*KEY_LENGTH}")
print(f"Ключі для користувача 1 ({KEY_LENGTH - 64} бітів для кожного простого):")
p1 = generate_safe_prime(KEY_LENGTH - 64)
print(f"p1 = {p1}")
q1 = generate_safe_prime(KEY_LENGTH - 64, [p1])
print(f"q1 = {q1}")

print()

print(f"Ключі для користувача 2 ({KEY_LENGTH + 64} бітів для кожного простого):")
p2 = generate_safe_prime(KEY_LENGTH + 64)
print(f"p2 = {p2}")
q2 = generate_safe_prime(KEY_LENGTH + 64, [p2])
print(f"q2 = {q2}")

# %% [markdown]
# ### Взаємодія користувачів
# 
# Так як для правильної взаємодії, що включає надсилання зашифрованого повідомлення і підпису для цього повідомлення необхідно, щоб виконувалась умова "ключ надсилача менший за ключ отримувача", ми створимо два користувачі для перевірки правильності взаємодії:
# 1. Надсилач секретного ключа.
# 2. Отримувач секретного ключа.
# %% [markdown]
# #### Взаємодія користувача 1 (Надсилач секретного ключа)

# %%
u_s = User(p1, q1)

u_s.send_message("Hello_Server1_from_U1")
u_s.send_message_sign("Hello_Server1_from_U1")
u_s.receive_message("Hello_User1_from_Server1")
u_s.receive_message_sign("Hello_User1_from_Server1")
u_s.send_secret_key("dfb0cd9586cf2d9ffff".capitalize())

# %% [markdown]
# #### Взаємодія користувача 2 (Отримувач секретного ключа)

# %%
u_r = User(p2, q2)

u_r.send_message("Hello_Server2_from_U2")
u_s.send_message_sign("Hello_Server2_from_U2")
u_r.receive_message("Hello_User2_from_Server2")
u_r.receive_message_sign("Hello_User2_from_Server2")
u_r.receive_secret_key()


