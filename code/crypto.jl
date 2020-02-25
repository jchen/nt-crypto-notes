# Addition (with BigInt and Int)
add(p::BigInt, a::BigInt, b::BigInt) = (a + b) % p
add(p, a, b) = add(BigInt(p), BigInt(a), BigInt(b))

# Subtraction
subtract(p::BigInt, a::BigInt, b::BigInt) = (a - b) % p
subtract(p, a, b) = subtract(BigInt(p), BigInt(a), BigInt(b))

# Multiplication
multiply(p::BigInt, a::BigInt, b::BigInt) = (a * b) % p
multiply(p, a, b) = multiply(BigInt(p), BigInt(a), BigInt(b))

# GCD
function gcd(a::BigInt, b::BigInt)
    r::BigInt = a % b
    if r == 0
        return b
    end
    return gcd(b, r)
end
gcd(a, b) = gcd(BigInt(a), BigInt(b))

# Extended Euclidian Algorithm
function extended_euclidian_alg(a::BigInt, b::BigInt)
    q = BigInt[]
    r::BigInt = a % b
    push!(q, div(a, b))
    while r != 0
        a = b
        b = r
        r = a % b
        push!(q, div(a, b))
    end
    return q
end
extended_euclidian_alg(a::Int64, b::Int64) =
    extended_euclidian_alg(BigInt(a), BigInt(b))

# Solving Linear Diophantine Equations
function solveLDE(a::BigInt, b::BigInt)
    P_n = BigInt(0)
    P_n_plus_one = BigInt(1)
    Q_n = BigInt(1)
    Q_n_plus_one = BigInt(0)
    q = extended_euclidian_alg(a, b)
    n = size(q)[1]
    parity = n % 2
    queue = 1
    while queue < n
        temp_P = P_n_plus_one
        next = q[queue]
        P_n_plus_one = P_n_plus_one * next + P_n
        P_n = temp_P
        temp_Q = Q_n_plus_one
        Q_n_plus_one = Q_n_plus_one * next + Q_n
        Q_n = temp_Q
        queue += 1
    end
    out = [P_n_plus_one Q_n_plus_one parity]
    return out
end

solveLDE(a, b) = solveLDE(BigInt(a), BigInt(b))

# Inverses
function inverse(p::BigInt, a::BigInt)
    solutions = solveLDE(p, a)
    return solutions[3] == 0 ? (p - solutions[1]) : solutions[1]
end

# Binary Representation (for fast powering algorithm)
function binary_representation(a::BigInt)
    out = Bool[]
    while a != 0
        next_bit = (a % 2) != 0
        pushfirst!(out, next_bit)
        a = div(a, 2)
    end
    return out
end

# Fast powering algorithm
function power(p::BigInt, a::BigInt, pow::BigInt)
    r = BigInt(1)
    for digit in binary_representation(pow)
        r = multiply(p, r, r)
        if digit
            r = multiply(p, r, a)
        end
    end
    return r
end

# Compositeness checker
function miller_rabin(p::BigInt)
    a::BigInt = rand(Int) % p
    if a == 1
        a = BigInt(rand(Int) % p)
    end
    k::BigInt = 0
    q::BigInt = p - 1
    while (q % 2 != 0)
        q = q % 2
        k += 1
    end
    a = BigInt(power(p, a, q))
    if a == 1
        return false
    end
    for i = 1:k
        if a == p - 1
            return false
        end
        a = multiply(p, a, a)
    end
    return true
end

# Primality Checker
function is_prime(p::BigInt)
    if p % 2 == 0
        return false
    end
    for i = 1:30
        if miller_rabin(p)
            return false
        end
    end
    return true
end

# Finds a candidate prime.
function candidate(size::BigInt)
    primes = [
        2 3 5 7 11 13 17 19 23 29 31 37 41 43 47 53 59 61 67 71
        73 79 83 89 97 101 103 107 109 113 127 131 137 139 149 151 157 163 167
        173 181 191 193 197 199 211 223 227 229 233 239 241 251 257 263 269 271
        277 281 283 293 307 311 313 317 331 337 347 349 353 359 367 373 379 383
        389 397 401 409 419 421 431 433 439 443 449 457 461 463 467 479 487 491 499
    ]
    multiple::BigInt = multiply(primes)
    rand_add::BigInt = multiply(primes)
    while (gcd(multiple, rand_add) != 1)
        rand_add = BigInt(rand(big"2":multiple))
    end
    k::BigInt = rand(big"1":big"2"^size)
    return BigInt((multiple * k) + rand_add)
end

# Multiplies elements of an array a together.
function multiply(a)
    sum::BigInt = BigInt(1)
    for num in a
        sum = sum * BigInt(num)
    end
    return sum
end

# Finds a prime number of magnitude size
function find_prime(size::BigInt)
    while true
        can::BigInt = candidate(size::BigInt)
        if is_prime(can)
            return can
        end
    end
end

# Generates a private and public key for ElGamal.
function elgamal_key(p::BigInt, g::BigInt)
    print("p: \n")
    print(p)
    print("\ng: \n")
    print(g)
    a::BigInt = rand(big"2":p)
    public = power(p, g, a)
    print("\nA: \n")
    print(public)
    print("\na (Private!): \n")
    print(a)
end

# Generates a full set of ElGamal Keys.
function elgamal_gen_keys()
    p = find_prime(BigInt(1000))
    g = rand(big"2":p)
    elgamal_key(p, g)
end

# Encrypts a message using the public key in ElGamal.
function elgamal_encrypt(p::BigInt, g::BigInt, A::BigInt, m::BigInt)
    k::BigInt = rand(big"2":p)
    c_1::BigInt = power(p, g, k)
    print("C_1: \n")
    print(c_1)
    c_2::BigInt = multiply(p, m, power(p, A, k))
    print("\nC_2: \n")
    print(c_2)
end

# Decrypts the message in ElGamal
function elgamal_decrypt(
    p::BigInt,
    g::BigInt,
    a::BigInt,
    c_1::BigInt,
    c_2::BigInt,
)
    x::BigInt = power(p, c_1, a)
    m::BigInt = multiply(p, c_2, inverse(p, x))
    print("m: \n")
    print(m)
    return m
end

# Uses Baby-Step Big-Step to bash the discrete log problem for g^x = A mod p
function bash_discrete_log(p::BigInt, g::BigInt, A::BigInt)
    m::BigInt = ceil(p - 1)
    tab = BigInt[]
    g_pow = 1
    for j = 1:m
        push!(tab, g_pow)
        g_pow = multiply(p, g_pow, g)
    end
    gamma = A
    for i = 0:(m-1)
        for idx = 1:m
            if gamma == tab[idx]
                return i * m + (idx - 1)
            end
        end
        gamma = multiply(p, gamma, inverse(power(p, a, m)))
    end
end
