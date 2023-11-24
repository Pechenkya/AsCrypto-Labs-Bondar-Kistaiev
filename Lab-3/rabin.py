# To add a new cell, type '# %%'
# To add a new markdown cell, type '# %% [markdown]'
# %% [markdown]
# # Лабораторна робота 3 з "Асиметричних криптосистем та протоколів"
# ## Тема: Криптосистема Рабіна. Атака на протокол доведення без розголошення.
# 
# **Виконали**\
# Бондар Петро, ФІ-03\
# Кістаєв Матвій, ФІ-03
# %% [markdown]
# Генерацію простих чисел та операції обчислення квадратних коренів за модулем ($n=pq$ та $p$) було спільним рішенням перенесено у файл ``optimus.py``.

# %%
import random as rnd
import requests
import sympy
from optimus import *

# %% [markdown]
# ## Взаємодія з віддаленим сервером
# 
# У якості сервера з яким ми будемо спілкуватися ми скористалися так званим Чорвером (**asymcryptwebservice**), який нам люб'язно надав Олег Миколайович.
# 
# Клас **Rabin_Server** дозволяє налагодити сесію спілкування з сервісом та надає зручний інтерфейс для надсилання запитів, що необхідні для цієї лабораторної роботи.

# %%
KEY_LENGTH = 512

class Rabin_Server:
    __base_url = 'http://asymcryptwebservice.appspot.com/rabin/'
    s = requests.Session()
    n = None
    b = None
    
    # Setup server private key and receive server pub key
    def set_server_key(self, key_l: int) -> (str, str):
        req = f'{self.__base_url}serverKey?keySize={key_l}'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        self.n, self.b = (int(r['modulus'], 16), int(r['b'], 16))
        return (self.n, self.b)
    
    # Ask server to encrypt
    def encrypt(self, M: str, rec_n, rec_b, type='TEXT'):
        req = f'{self.__base_url}encrypt?modulus={format(rec_n, "X")}&b={format(rec_b, "X")}&message={M}&type={type}'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        return (r['cipherText'], r['parity'], r['jacobiSymbol'])
    
    # Ask server to decrypt this message with his private keys
    def decrypt(self, C: str, p: int, j: int, type='TEXT'):
        req = f'{self.__base_url}decrypt?cipherText={C}&expectedType={type}&parity={p}&jacobiSymbol={j}'
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
    def verify(self, M: str, sign: str, u_n, type='TEXT'):
        req = f'{self.__base_url}verify?message={M}&type={type}&signature={sign}&modulus={format(u_n, "X")}'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        return r['verified']

# %% [markdown]
# ### Службові функції перетворення
# 
# Іноді дані необхідно відправити у певному форматі, а бо вони приходять у цьому форматі.
# 
# Для перетворення даних між різними формами довелося імплементувати методи **str2hex** та **num2str**.
# 
# Також додані методи додавання та знімання падінгу до/з повідомлення.

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

def rabin_format(X: int):
    return 255*(2**(KEY_LENGTH*2 - 16)) + X * (2**64) + random.randrange(0, 2**64)

def rabin_unformat(X: int):
    return (X % (pow(2, (KEY_LENGTH*2 - 16)))) // (2**64)

# %% [markdown]
# ### Абстракція користувача
# 
# Для спілкування необхідний абонент, що буде надсилати, отримувати та оброблювати запити від сервера. Для цього створений клас **Rabin_User**:
# 
# 1. При ініціалізації він приймає значення **p** та **q**, що будуть його публічним ключем, а також опціонально параметр **b** та сервер. У випадку відсутності заданого сервера створиться новий об'єт та запуститься нова сесія спілкування з сервером. В будь-якому випадку, при створенні коритсувача будуть заново згенеровані публічний та особистий ключ на стороні сервера, що буде використовуватись під час взаємодіїю
# 2. Метод **send_message** дозволяє зашифрувати та надіслати повідомлення **M** серверу відповідно до протоколу спілкування. У відповідь користувач повинен розшифроване сервером повідомлення.
# 3. Метод **send_message_sign** дозволяє отримати підпис **S** для повідомлення **M** та надіслати цю пару серверу напряму для верифікації підпису.
# 4. Метод **receive_message** дозволяє надіслати серверу відкрито повідомлення **M** та отримати його у зашифрованому вигляді. 
# 5. Метод **receive_message_sign** дозволяє надіслати серверу відкрито повідомлення **M** та отримати відкрито підпис для цього повідомлення.
# 
# В кожному методі результати взаємодії перевіряються та результат перевірки надається користувачу.
# 
# 
# #### Доповнення повідомлення
# 
# Повідомлення $m$ для стійкості доповнюється паддінгом наступним чином:
# \begin{equation}
#     x \leftarrow 0x00 || 0xFF || \underbrace{m}_{l*2 - 10 \; bytes} || \underbrace{r}_{8 \; bytes}
# \end{equation}
# 
# #### Розширена схема шифрування за Рабіним
# 
# Шифротекст $(y, c_1, c_2)$ обчислюється за наступними формулами:
# \begin{gather}
#     y = x(x + b) \;mod\,n \\
#     c_1 = \left(\left(x + \frac{b}{2}\right)\;mod\,n\right) \;mod\,2 \\
#     c_2 = \left(\frac{x+\frac{b}{2}}{n}\right)
# \end{gather}
# 
# Розшифрування відбувається у два кроки:
# 1. Обчислення наступного квадратного кореня (він має 4 розв'язки):
# \begin{equation}
#     x' \equiv \sqrt{y + \frac{b^2}{4}} \;(mod\,n)
# \end{equation}
# 2. Серед розв'язків порівняння обирається єдиний корінь $x'$, що задовільняє задані $c_1$ та $c_2$.
# 3. Після чого власне зашифроване $x$ отримується наступним чином:
# \begin{equation}
#     x = \frac{b}{2} + x' \;mod\,n
# \end{equation}

# %%
class Rabin_User:
    def __init__(self, p, q, b = 0, serv = Rabin_Server()):
        print("Initializing user...")
        if not check_prime(p) or not check_prime(q):
            raise RuntimeError("p or q is not a prime number.")
        
        self.serv = serv
        self.p = p
        self.q = q
        self.b = b
        self.n = p*q
        self.get_server_public_key(KEY_LENGTH * 2)

        print(f"User private key (p, q): {(self.p, self.q)}")
        print(f"User public key (n, b): {(self.n, self.b)}")
        print(f"User server public key (n, b): {(self.serv.n, self.serv.b)}")
        print("--------------------------------------------------------")
    

    def get_server_public_key(self, len: int):
        self.serv.set_server_key(len)


    def send_message(self, M: str):
        print("Sending message to the server...")
        print(f"Sent message: {M}")

        M_format = rabin_format(int(str2hex(M), 16))
        
        c1 = ((M_format + (self.serv.b * pow(2, -1, self.serv.n))) % self.serv.n) % 2
        c2 = int(sympy.jacobi_symbol(M_format + (self.serv.b * pow(2, -1, self.serv.n)), self.serv.n) == 1)
        C = format(M_format*(M_format + self.serv.b) % self.serv.n, "X")
        print(f"Sent cyphertext: {(C, c1, c2)}")
        

        M1 = self.serv.decrypt(C, c1, c2)
        print(f"Server responce: {M1}")

        check = (M1 == M)
        if check:
            print("Success")
        else:
            print("Error")
        print("--------------------------------------------------------")


    def send_message_sign(self, M: str):
        print("Sending signature to the server...")
        print(f"Sent message: {M}")
        
        X = rabin_format(int(str2hex(M), 16))
        while not (sympy.jacobi_symbol(X, self.p) == 1 and sympy.jacobi_symbol(X, self.q) == 1):
            X = ((X >> 64) << 64) + random.randrange(0, 2**64)

        Roots = sqrt_modpq(X, self.p, self.q)

        S = format(Roots[random.randrange(0, 4)], "X")
        print(f"Sent signature: {S}")

        check = self.serv.verify(M, S, self.n)
        if check:
            print("Success")
        else:
            print("Error")
        print("--------------------------------------------------------")


    def receive_message(self, M: str):
        print("Sending request for message to the server...")
        print(f"Sent message: {M}")
        
        C, b1, b2 = self.serv.encrypt(M, self.n, self.b)
        print(f"Received cyphertext: {C}")

        Roots = sqrt_modpq((int(C, 16) + (pow(self.b, 2, self.n) * pow(2, -2, self.n)) % self.n), self.p, self.q)
        for m in Roots:
            if [b1, b2] == [(m % self.n) % 2, (sympy.jacobi_symbol(m, self.n) == 1)]:
                M1 = (m - (self.b * pow(2, -1, self.n))) % self.n
                break
        
        M2 = num2str(rabin_unformat(M1))
        print(f"Decoded cyphertext: {M2}")

        check = (M == M2)
        if check:
            print("Success")
        else:
            print("Error")
        print("--------------------------------------------------------")
        
        
    def receive_message_sign(self, M: str):
        print("Sending request for message signature to the server...")
        print(f"Sent message: {M}")
        
        S = self.serv.sign(M)
        print(f"Received signature: {S}")
        M1 = num2str(rabin_unformat(pow(int(S, 16), 2, self.serv.n))) 
        print(f"Message signed with signature: {M1}")
        
        check = (M1 == M)
        if check:
            print("Success")
        else:
            print("Error")
        print("--------------------------------------------------------")

# %% [markdown]
# ## Симуляція взаємодії (використання протоколу Рабіна)
# %% [markdown]
# ### Генерація простих чисел Блюма для ключа користувача

# %%
print(f"Довжина модуля сервера: {2*KEY_LENGTH}")
print(f"Ключі для користувача ({KEY_LENGTH} бітів для кожного простого):")
p1 = generate_blum_prime(KEY_LENGTH)
print(f"p1 = {p1}")
q1 = generate_blum_prime(KEY_LENGTH, [p1])
print(f"q1 = {q1}")

# %% [markdown]
# ### Створення користувача та надсилання всіх доступних йому запитів

# %%
u_r = Rabin_User(p1, q1, b=rnd.randrange(0, p1*q1))
u_r.send_message("sdjdfgjdhgfjdgfhj")
u_r.receive_message("Asdjsghdfhisjdfh!")
u_r.send_message_sign("Hello!")
u_r.receive_message_sign("Hello!")

# %% [markdown]
# ## Атака на протокол доведення без розголошення (так званий Zero kNowledge Proof)
# 
# Для взаємодії з сервером створено класи **ZNP_Server** та **ZNP_User**.
# 
# Необхідно отримати приватний ключ сервера (розклад $n=pq$).
# 
# Користувач налагоджує спілкування з віддаленим сервером та отримує публічний ключ, після чого ми маємо можливість почати атаку.
# Так як нам відомо, що квадратний корінь, що поверне сервер буде квадратичним лишком, то в якості нашого випадкового кореня підберемо якийсь квадратичний нелишок.
# Отримавши значення другого кореня, скористаємось тим, що $X^2 \equiv Y^2 (mod n)$, з цього ми отримаємо, що $p = \gcd(X - Y, n)$, a $q = \gcd(X + Y, n)$.

# %%
class ZNP_Server:
    __base_url = 'http://asymcryptwebservice.appspot.com/znp/'
    s = requests.Session()
    n = None
    
    # Setup server private key and receive server pub key
    def set_server_key(self) -> (str, str):
        req = f'{self.__base_url}serverKey'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        self.n = int(r['modulus'], 16)
        return self.n
    
    def take_sqrt_mod_n(self, y):
        req = f'{self.__base_url}challenge?y={format(y, "X")}'
        print(f"H: Sent request: {req}")
        r = self.s.get(req)
        if r.status_code != 200:
            raise RuntimeError(f"Incorrect server status code {r.status_code}:\n\tRequest {req}\n\tResponse{r.json()}")
        r = r.json()
        print(f"S: Response: {r}")
        return r['root']


class ZNP_User:
    def __init__(self, serv = ZNP_Server()):
        print("Initializing user...")
        
        self.serv = serv
        self.get_server_public_key()

        print(f"User server public key (n): {self.serv.n}")
        print("--------------------------------------------------------")

    def get_server_public_key(self):
        self.serv.set_server_key()

    # Ask server to 
    def attack_server(self):
        print("Starting ZNP attack...")

        print(f"Server public key: {self.serv.n}")

        itr = 0
        while True:
            x1 = rnd.randint(1, self.serv.n)
            itr += 1

            if sympy.jacobi_symbol(x1, self.serv.n) != -1:
                continue
            print(f"Randomed {itr} times")

            print("\n==== Asking to take root =====")
            x2 = int(self.serv.take_sqrt_mod_n(pow(x1, 2, self.serv.n)), 16)
            print("=======================")
            print(f"\nCandidate: {x2}")
            
            if x1 != x2 and x1 != ((-x2) % self.serv.n):
                print("Candidate is OK!")
                break
            else:
                print("Reroll!")

        p = math.gcd(x1 - x2, self.serv.n)
        # q = math.gcd(x1 + x2, self.serv.n)
        q = self.serv.n // p

        print("\n== Results ==")
        print(f"p: {p}")
        print(f"q: {q}")
        print(f"p*q: {p*q}")
        print("==========\n")

        check = (p*q == self.serv.n)
        if check:
            print("Success!")
        else:
            print("No Success. ЩЗХ? :(")
        
        print("--------------------------------------------------------")


# %%
znp_u = ZNP_User()
znp_u.attack_server()


