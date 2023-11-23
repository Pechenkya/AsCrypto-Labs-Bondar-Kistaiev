import numpy as np
import math
import random

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
        
# Генератор блум простих чисел
def generate_blum_prime(len: int, excl = []):
    while True:
        p = generate_prime(len, excl)
        if p % 4 == 3:
            return p


def CRT(a, n):
    n_prod = math.prod(n)
    N = [n_prod // n_i for n_i in n]
    M = [pow(n_prod // n_i, -1, n_i) for n_i in n]

    return sum([a[i]*M[i]*N[i] for i in range(0, len(a))]) % n_prod

def jacobi(a, n):
    a = int(a)
    a = a % n
    
    if math.gcd(a, n) != 1:
        return 0

    if a == 1:
        return 1

    if a > n:
        return jacobi(a % n, n)

    if a % 2 == 0:
        if n % 8 == 1 or n % 8 == 7:
            return jacobi(a // 2, n)
        else:
            return (-1) * jacobi(a // 2, n)

    if n % 4 == 1 or a % 4 == 1:
        return jacobi(n, a)
    else:
        return (-1) * jacobi(n, a)


def sqrt_modp(a, p):
    a = a % p

    if jacobi(a, p) != 1:
        print(f"error a = {a}, p = {p}")

    if p % 4 == 3:
        # print("4k + 3")
        sq_a = pow(a, (p + 1) // 4, p)
        return [sq_a, p - sq_a]
    
    if p % 8 == 5:
        # print("8k + 5")
        k = (p - 5) // 8
        if pow(a, 2*k + 1, p) == 1:
            sq_a = pow(a, k + 1, p)
        else:
            sq_a = (pow(a, k + 1, p) * pow(2, 2*k + 1, p)) % p

        return[sq_a, p - sq_a]
    
    if p % 8 == 1:
        # print("8k + 1")
        b = 2
        while jacobi(b, p) != -1:
            b = random.randrange(3, p - 1)

        t_a = (p - 1) // 2
        t_b = 0

        while t_a % 2 == 0:
            if (pow(a, t_a, p) * pow(b, t_b, p)) % p  == p - 1:
                t_b += (p - 1) // 2

            t_a = t_a // 2
            t_b = t_b // 2

        if (pow(a, t_a, p) * pow(b, t_b, p)) % p  == p - 1:
                t_b += (p - 1) // 2

        sq_a = (pow(a, (t_a + 1) // 2, p) * pow(b, t_b // 2, p)) % p
        return[sq_a, p - sq_a]
    

def sqrt_modpq(a, p, q):
    a = a % (p*q)

    x1, x2 = sqrt_modp(a, p)
    x3, x4 = sqrt_modp(a, q)

    sqa_1 = CRT([x1, x3], [p, q])
    sqa_2 = CRT([x1, x4], [p, q])
    sqa_3 = CRT([x2, x3], [p, q])
    sqa_4 = CRT([x2, x4], [p, q])

    return [sqa_1, sqa_2, sqa_3, sqa_4]