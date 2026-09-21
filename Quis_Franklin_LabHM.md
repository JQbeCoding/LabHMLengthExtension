# Lab: Hashing & Message Authentication Codes (MAC)

Submit as: Quis_Franklin_LabHM.docx (paste this into Word, insert your screenshots).

---

## Part 0: Student Identity Parameters

| Symbol | Value |
|--------|--------|
| NAME | quisfranklin |
| SID | 801480194 |
| SIP | quisfranklin-801480194 |
| FIRST | quis |
| PASS | quisfranklin-801480194!94 |

---

## Part 1: Hash Properties, Avalanche Effect & a First MAC

### Recorded values

| Item | Value |
|------|--------|
| SIP | quisfranklin-801480194 |
| Changed SIP (one character) | juisfranklin-801480194 (first letter q → j) |
| D1 (SHA2-256 of SIP) | c4e226ebeb50dcfac011bb2a8472c24c2175f63e3235b92cc7a58e5e80f47359 |
| D2 (SHA2-256 of changed SIP) | 476d652b59151a0475c772875b44af7b1b7405e6ba4d3d4ffa555d5f687446eb |
| Hamming distance | 126 / 256 bits (fraction 126/256 ≈ 0.492) |
| MD5(SIP) | 0cbc93abb5a9edcf13fa4a6d373f91ac (128 bits) |
| SHA1(SIP) | ca3ae74e3816231ea5d2a616f4f6bbe957d77b04 (160 bits) |
| SHA2-256(SIP) | c4e226ebeb50dcfac011bb2a8472c24c2175f63e3235b92cc7a58e5e80f47359 (256 bits) |
| SHA3-256(SIP) | 2423eb9e649ab91978a716008a34c5fa93026d70d58a4505d40045da2ff8b8b5 (256 bits) |
| T1 HMAC-SHA256(key=quis, msg=SIP) | 3e92403dd1a6f7a1bb6d12a8c998a730b1a1f6c7165562e6f97b8a3a16d7d82c |
| T2 HMAC-SHA256(key=quis5, msg=SIP) | a2469f95857a2a017549ac60e18e05951c88c00650ae964e1df8cbd8194de5dd |

Key change for T2: appended hex character `5` to FIRST, so key = `quis5`.

### Screenshot checklist (SS1–SS3)

CyberChef: https://uncc-fortress.github.io/CyberChef/ (or https://gchq.github.io/CyberChef/)

Full-desktop screenshots (menu bar + clock visible). Yellow highlight on inputs/outputs as noted; red boxes on boxed values.

- SS1: Operation SHA2, size 256. Input = SIP. Highlight input yellow; box D1 red.
- SS2: Same recipe with changed SIP `juisfranklin-801480194`. Box the changed `j` red. Show Hamming: either CyberChef From Hex → XOR (other digest as Hex key) → To Binary and count 1s, or Python `bin(int(D1,16)^int(D2,16)).count("1")` → 126. Keep D2 and the distance visible.
- SS3: HMAC, SHA256, key type UTF8 (not Hex), key `quis`, input SIP → T1 (box key and T1 red). Then key `quis5` → T2 (different tag visible).

### Analysis

Q1. My Hamming distance was 126 out of 256 bits, which is 126/256 ≈ 0.492. That is the avalanche effect: a one-character change flipped about half the output bits. An ideal hash should flip close to half the bits on any small input change. If a signature hashed the message first and the hash lacked avalanche, two almost-identical messages could produce digests that look related, so an attacker could tweak a message while keeping the signed digest in a predictable range. Avalanche makes small edits look like random new digests.

Q2. For an ideal n-bit hash, a generic preimage attack costs about O(2^n) work, and a generic collision attack costs about O(2^{n/2}) work (birthday bound). Concrete exponents:

| Hash | n | Preimage | Collision |
|------|---|----------|-----------|
| MD5 | 128 | 2^128 | 2^64 |
| SHA-256 | 256 | 2^256 | 2^128 |

Q3. (a) From T1 alone, with SIP public and the key unknown, an attacker cannot recover the key or produce a valid new tag for a modified message in a practical way. The tag looks like a random 256-bit string; it does not reveal SIP beyond what they already see in the clear. (b) Sending SIP next to plain SHA256(SIP) can catch accidental bit flips, because a corrupted message will not rehash to the same digest. It does not stop a deliberate attacker: they can change SIP to SIP' and replace the digest with SHA256(SIP'). Anyone can compute an unkeyed hash. A MAC needs the secret key, so only someone who holds the key can make a tag Bob will accept.

---

## Part 2: Collisions

### Recorded values

Expected MD5 of both blocks: `79054025255fb1a26e4bc422aef54eb4`

| Block | MD5 | SHA2-256 |
|-------|-----|----------|
| A | 79054025255fb1a26e4bc422aef54eb4 | 8d12236e5c4ed9f4e790db4d868fd5c399df267e18ff65c1107c328228cffc98 |
| B | 79054025255fb1a26e4bc422aef54eb4 | b9fef2a8fc93b05e7701e97196fda6c4fbeea25ff8e64fdfee7015eca8fa617d |

A ≠ B: they differ in 6 bytes (indices 19, 45, 59, 83, 109, 123).

Block A hex (From Hex input):

```
d131dd02c5e6eec4693d9a0698aff95c2fcab58712467eab4004583eb8fb7f8955ad340609f4b30283e488832571415a085125e8f7cdc99fd91dbdf280373c5bd8823e3156348f5bae6dacd436c919c6dd53e2b487da03fd02396306d248cda0e99f33420f577ee8ce54b67080a80d1ec69821bcb6a8839396f9652b6ff72a70
```

Block B hex:

```
d131dd02c5e6eec4693d9a0698aff95c2fcab50712467eab4004583eb8fb7f8955ad340609f4b30283e4888325f1415a085125e8f7cdc99fd91dbd7280373c5bd8823e3156348f5bae6dacd436c919c6dd53e23487da03fd02396306d248cda0e99f33420f577ee8ce54b67080280d1ec69821bcb6a8839396f965ab6ff72a70
```

### Screenshot checklist (SS4–SS5)

- SS4: From Hex → MD5 for A and for B. Both digests `79054025…`. Highlight the matching digests yellow.
- SS5: From Hex → SHA2 (256) for A and B. Different digests visible.

### Analysis

Q4. By the birthday bound, a random collision on a 128-bit hash is expected around 2^{64} trials. Chosen-prefix MD5 attacks that need about 2^{39} work (or less) are far cheaper than that. The gap means MD5 is broken by cryptanalysis of its design, not because brute force suddenly became cheap on its own. The weakness is differential cryptanalysis of MD5’s compression function (structured differences that cancel through the rounds).

Q5. (a) A collision is about one specific function. MD5 and SHA-256 use different compression functions and initial states, so two inputs that collide under MD5 are almost certain to produce different SHA-256 digests, which is what we saw. (b) A collision is any pair of distinct inputs with the same hash. A second-preimage is: given a fixed target input x, find a different x' with H(x') = H(x). For “here is a contract, sign its hash,” second-preimage resistance is what you want: nobody should be able to replace your contract with another document that still verifies under the same signature. Collisions still matter in other settings (two crafted documents prepared in advance), but the classic signed-contract story is second-preimage.

Q6. One concrete collision attack is a colliding pair of X.509 certificates (or colliding PDF / executable pairs in the SHAttered SHA-1 style). The attacker builds two artifacts that hash the same: a benign-looking certificate (or document) and a malicious one. A CA or user signs/trusts the benign hash; that signature also validates the malicious artifact because the digests match. The collision is what makes the trusted signature transfer to the bad file.

---

## Part 3: Length-Extension Attack vs. HMAC

### What you must run and capture (I did not run the forgery for you)

Working directory: `/Users/jaquismay/Downloads/LabHM`

```bash
cd /Users/jaquismay/Downloads/LabHM
python3 sha256_lenext.py --first quis
python3 sha256_lenext.py --first quis --hmac
```

Then push `sha256_lenext.py` to a public GitHub repo titled `LabHM_LengthExtension` and put the link here:

GitHub repo: ________________________________

Screenshot checklist (SS6–SS9):

- SS6: Legitimate guest token generated and verified True.
- SS7: Successful forgery against the naive MAC (recovered secret length boxed red, ACCEPTED highlighted yellow, `role=admin` visible). Full desktop.
- SS8: Same forgery rejected under `--hmac`.
- SS9: CyberChef HMAC-SHA256, key type Hex = revealed secret from the `--hmac` run, input = legitimate message; tag matches the script’s legit tag (highlight matching tags yellow).

### Analysis (concepts)

Q7. Merkle–Damgård hashes process the message in fixed-size blocks and keep an internal chaining state. The published digest is essentially that final chaining state (plus the padded length already mixed in). If you know H(secret || m) and the bit length of secret || m, you know the state the hash machine would have after finishing that padded string. You can resume from that state, feed more blocks for a chosen suffix, and get H(secret || m || glue_padding || suffix) without knowing secret. The property that makes the digest a resumable state is that MD exposes the full chaining value as the output and pads in a way an outsider can reconstruct once the length is known.

Q8. Query-string parsers usually split on `&` and `=` and treat other bytes as part of values. Glue padding (0x80, zeros, length field) sits inside a value field; many parsers never reject “weird” bytes. So “malformed bytes would be noticed” is a weak defense: the parser often still yields `role=admin` as the last assignment.

Q9. HMAC is H((k ⊕ opad) || H((k ⊕ ipad) || m)). The tag you see is the outer hash. Length-extending that outer digest would continue hashing as if the outer input were being extended, but a valid HMAC for a longer message needs a new inner hash of (k ⊕ ipad) || m' first, then the outer hash of that. The attacker holds only the outer digest, not the inner state under the keyed ipad, so they cannot produce a tag that equals HMAC(k, m || …).

Q10. Two fixes other than HMAC:

1. Hash twice with the secret, e.g. H(secret || H(secret || m)) or a nested construction: the outer hash’s input depends on a secret-influenced inner digest, so extending the outer tag does not give a tag for a longer message under the same construction.
2. Switch to a sponge / SHA-3 or KMAC: the output is a truncated squeeze of a larger state, not the full internal state, so the digest is not enough to resume absorption the way MD allows. (CMAC with a block cipher is another keyed construction that is not “secret-prefix MD.”)

Q11. Merkle–Damgård outputs the full chaining state after the last block. A sponge keeps a larger internal state; the hash output is only a truncated squeeze of that state. The capacity bits never appear in the digest, so an attacker who sees SHA3-256(x) does not have enough state to continue absorbing as if they were the real hash function. That is why SHA-3 / KMAC resist the same length-extension pattern that hits SHA-256(secret || m).

---

## Part 4: Password Hashing & KDFs

### Console results (from this machine)

Command:

```bash
python3 password_kdf_bench.py --passphrase "quisfranklin-801480194!94"
```

Unsalted SHA-256(PASS):

`6343305f0f6a0d6fbad361e591e1b3d218ac90e2882dd29876e65094651cda51`

Your screenshot run (salts are random each run):

| | Value |
|--|--------|
| salt A | (from your SS10 console) |
| SHA256(saltA \|\| PASS) | (from your SS10 console; different from B) |
| salt B | (from your SS10 console) |
| SHA256(saltB \|\| PASS) | (from your SS10 console; different from A) |

Timing table from your SS11 run:

| algorithm | time / hash | est. GPU guesses/sec |
|-----------|-------------|----------------------|
| raw SHA-256 | 0.1 us | 20,000,000,000 |
| PBKDF2-HMAC-SHA256 ×10,000 | 1.39 ms | 1,000,000 |
| PBKDF2-HMAC-SHA256 ×100,000 | 13.30 ms | 100,000 |
| PBKDF2-HMAC-SHA256 ×600,000 | 62.03 ms | 16,666 |
| scrypt N=2^15,r=8,p=1 | 61.80 ms | memory-hard (~32 MiB per guess) |

### Screenshot checklist (SS10–SS12)

- SS10: Console showing one unsalted digest and two different salted digests; highlight the two salted digests yellow.
- SS11: Timing table; box times and est. guessing rates red.
- SS12: CyberChef → Bcrypt, rounds = 10, input = `quisfranklin-801480194!94`. Bake twice. Two different `$2…` strings; box the differing salt portions. (Bcrypt embeds a fresh random salt each time.)

### Analysis

Q12. A salt defeats precomputed attacks on common passwords: rainbow tables and identical hash reuse across users. Each password gets a unique stored value, so one table does not crack every account that shared a password. The iteration count (work factor) defeats fast online/offline guessing of that specific hash: each guess costs more CPU time, so brute force and dictionary attacks slow down. Salt does not make a single guess expensive; iterations do. Iterations do not stop two users with the same password from looking the same if you forgot the salt.

Q13. On my machine every PBKDF2 setting finished under ~250 ms. I pick PBKDF2-HMAC-SHA256 with 600,000 iterations (62.03 ms per verification). From the table, raw SHA-256 is estimated at 20,000,000,000 GPU guesses/sec and that PBKDF2 setting at 16,666 guesses/sec. Drop factor:

20,000,000,000 / 16,666 ≈ 1,200,048 ≈ 1.2 × 10^6

So offline guessing is about 1.2 million times slower than raw SHA-256 at that work factor (using the script’s GPU estimate column).

Q14. A GPU or ASIC is built to run many parallel cheap hashes with little memory per core. A large memory requirement per guess (scrypt/Argon2) forces each parallel lane to hold tens of megabytes. That cuts how many guesses fit on the card and kills the throughput advantage. Raising only an iteration count still lets the attacker keep thousands of tiny SHA-2 pipelines busy; memory-hardness attacks that parallelism.

Q15. If login (or password-change) calls a slow KDF on every attempt, an attacker can open many parallel login requests and burn CPU/memory on the server (CPU exhaustion DoS). A standard mitigation is rate limiting (and lockouts / CAPTCHA / proof-of-work) on authentication endpoints so an attacker cannot force unlimited slow hashes. Caching is not a substitute for that on failed guesses.

---

## AI appendix (required)

I used Cursor (an AI coding assistant) to help organize this report, compute hash digests with Python’s hashlib for Parts 1–2 and 4, and draft analysis answers. I ran CyberChef and Part 3 screenshots myself. I reviewed the answers against the lab prompts and can explain the underlying ideas (avalanche, birthday bound, collisions vs second-preimages, Merkle–Damgård length extension vs HMAC/sponge, salt vs work factor).

---

## Paste-into-Word order

1. Part 0 table  
2. Part 1 values + SS1–SS3 + Q1–Q3  
3. Part 2 values + SS4–SS5 + Q4–Q6  
4. Part 3 GitHub link + SS6–SS9 + Q7–Q11  
5. Part 4 values + SS10–SS12 + Q12–Q15  
6. AI appendix  
