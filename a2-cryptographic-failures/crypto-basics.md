# Crypto Basics — WebGoat Lesson: A2 Cryptographic Failures

**Category:** A2 — Cryptographic Failures
**Difficulty:** Medium

## Objective

This is a multi-part lesson covering the full spectrum of cryptographic basics and their common misuses: Base64/Basic Authentication, XOR "encryption," plain unsalted password hashing, RSA digital signatures, and a practical exercise finding a hardcoded secret baked into a Docker image. Each part demonstrates a different way cryptographic primitives get misused in real applications.

## Vulnerability

Collectively, these exercises demonstrate the same underlying theme: **encoding is not encryption, and weak or absent cryptography provides no real protection**. Specifically:
- Base64 and XOR "encoding" are trivially reversible with no secret key involved.
- Unsalted hashes (MD5, SHA-256 without a salt) are vulnerable to precomputed lookup-table attacks (rainbow tables).
- Secrets baked directly into container images/filesystems are retrievable by anyone with access to the image or a running container.

## Part 1 — Base64 Encoding / Basic Authentication

**Task:** Given an intercepted `Authorization: Basic cGVwbzExOnBhc3N3MHJk` header, recover the username and password.

![Lesson intro: Base64 encoding and Basic Auth](../assets/a2-cryptographic-failures/crypto-basics/01-stage-basic-auth-intro.png)

HTTP Basic Authentication just Base64-encodes `username:password` — no hashing, no encryption. Decoded the intercepted value directly using an online Base64 decoder:

```
cGVwbzExOnBhc3N3MHJk  →  pepo11:passw0rd
```

![Base64-decoding the intercepted credentials](../assets/a2-cryptographic-failures/crypto-basics/02-base64-decode-credentials.png)

Submitted username `pepo11` and password `passw0rd` — correct:

![Basic Auth exercise solved](../assets/a2-cryptographic-failures/crypto-basics/03-basic-auth-correct.png)

## Part 2 — XOR Encoding

**Task:** Recover the original password from a WebSphere-style XOR-"encoded" string: `{xor}Oz4rPj0+LDovPiwsKDAtOw==`.

![Lesson intro: XOR encoding assignment](../assets/a2-cryptographic-failures/crypto-basics/04-xor-encoding-intro.png)

IBM WebSphere's `{xor}` password obfuscation XORs each byte against a single well-known, hardcoded byte (`0x5F`) and then Base64-encodes the result — it's a known, publicly documented scheme, not real encryption. Used a dedicated WebSphere XOR decoder tool to reverse it directly:

![Decoding the {xor} string using a WebSphere XOR decoder tool](../assets/a2-cryptographic-failures/crypto-basics/05-xor-decoder-tool-result.png)

This revealed the plaintext password `databasepassword`. Submitted it — correct:

![XOR exercise solved](../assets/a2-cryptographic-failures/crypto-basics/06-xor-correct.png)

## Part 3 — Plain (Unsalted) Hashing

**Task:** Identify the plaintext passwords behind two unsalted hashes:
```
BED128365216C019988915ED3ADD75FB                                   (MD5)
2BB80D537B1DA3E38BD30361AA855686BDE0EACD7162FEF6A25FE97BF527A25B    (SHA-256)
```

![Lesson intro: plain hashing assignment](../assets/a2-cryptographic-failures/crypto-basics/07-hash-cracking-intro.png)

Since these are unsalted, they're vulnerable to precomputed lookup tables — ran both through CrackStation, which cracked them instantly:

![CrackStation results for both hashes](../assets/a2-cryptographic-failures/crypto-basics/08-crackstation-results.png)

- MD5 hash → `passw0rd`
- SHA-256 hash → `secret`

Submitted both — correct:

![Hash cracking exercise solved](../assets/a2-cryptographic-failures/crypto-basics/09-hash-cracking-correct.png)

## Part 4 — RSA Digital Signatures

**Task:** Given a private RSA key, determine its modulus as a hex string, then produce a valid signature over that hex string using the same key.

![Assignment: RSA modulus and signature](../assets/a2-cryptographic-failures/crypto-basics/12-rsa-signature-correct.png)

Saved the provided private key to a file named `webgoat`, then extracted the modulus using OpenSSL, stripped the `Modulus=` prefix with `sed`, and removed the trailing newline with `tr`:

```bash
openssl rsa -in webgoat -noout -modulus | sed 's/^Modulus=//' | tr -d '\n' > modulus.txt
```

Verified the extracted modulus looked correct with `xxd`:

![Extracting and verifying the RSA modulus](../assets/a2-cryptographic-failures/crypto-basics/10-rsa-modulus-extraction.png)

Then produced the actual signature: wrote the clean modulus hex string to a file, signed it with the private key using SHA-256, and Base64-encoded the resulting binary signature for submission:

```bash
printf '%s' "$(cat modulus.txt)" > modulus_clean.txt
openssl dgst -sha256 -sign webgoat -out signature.bin modulus_clean.txt
base64 -w 0 signature.bin
```

![Signing the modulus and generating the Base64 signature](../assets/a2-cryptographic-failures/crypto-basics/11-rsa-sign-modulus.png)

Submitted both the modulus hex string and the Base64 signature — correct:

*(see screenshot above for the success confirmation)*

## Part 5 — Hardcoded Secrets in Docker Images

**Task:** A secret was accidentally left inside a Docker image. Retrieve it, then use it to decrypt a given AES-256-CBC encrypted message: `U2FsdGVkX199jgh5oANElFdtCxIEvdEvciLi+v+5loE+VCuy6Ii0b+5byb5DXp32RPmT02Ek1pf55ctQN+DHbwCPiVRfFQamDmbHBUpD7as=`.

![Assignment: find the secret in a Docker image and decrypt the message](../assets/a2-cryptographic-failures/crypto-basics/13-docker-secret-intro.png)

Started the provided image and explored the running container (a couple of exploratory commands like `docker status` failed since it isn't a real Docker subcommand — confirmed available images instead):

```bash
docker run -d webgoat/assignments:findthesecret
docker images | grep -i webgoat
```

![Running the container and exploring available images](../assets/a2-cryptographic-failures/crypto-basics/14-docker-run-and-explore.png)

Opened a shell inside the running container and found a `default_secret` file sitting in `/root`:

```bash
docker exec -it -u 0 285417b94f73 /bin/bash
ls -la /root
cat /root/default_secret
```

This revealed the secret password: `ThisIsMySecretPassw0rdForYOu`. Used it as the decryption key for the provided ciphertext:

```bash
echo "U2FsdGVkX199jgh5oANElFdtCxIEvdEvciLi+v+5loE+VCuy6Ii0b+5byb5DXp32RPmT02Ek1pf55ctQN+DHbwCPiVRfFQamDmbHBUpD7as=" | openssl enc -aes-256-cbc -d -a -kfile /root/default_secret
```

Which decrypted to the plaintext message: **"Leaving passwords in docker images is not so secure"**

![Decrypting the secret message using the recovered password](../assets/a2-cryptographic-failures/crypto-basics/15-docker-exec-decrypt-secret.png)

Submitted the decrypted message and the filename (`default_secret`) — correct:

![Docker secrets exercise solved](../assets/a2-cryptographic-failures/crypto-basics/16-docker-secret-correct.png)

## Why It Worked

- **Base64/XOR are encodings, not encryption** — fully reversible by anyone, with no secret key required. They provide zero confidentiality against an attacker who intercepts the data.
- **Unsalted hashes are vulnerable to precomputed attacks** — identical plaintexts always produce identical hashes, so public rainbow-table/lookup services like CrackStation can reverse common passwords in seconds.
- **RSA signatures rely entirely on private key secrecy** — this part wasn't a vulnerability demo so much as a practical exercise in how asymmetric signing actually works end-to-end using standard tooling.
- **Secrets baked into container images persist in the image/filesystem** — anyone who can pull or run the image (or access a running container) can read any file left inside it, including "default" credentials meant to be temporary or placeholder values.

## Remediation

- Never treat encoding (Base64, hex, XOR, URL-encoding) as a security control. Use these only for data transport/formatting, never for protecting secrets.
- Always use TLS/HTTPS when transmitting Basic Authentication credentials, since Base64 offers no confidentiality on its own.
- Replace unsalted hashing for passwords with a proper password hashing algorithm that includes a per-user salt and is deliberately slow (e.g., bcrypt, scrypt, or Argon2) — never MD5 or SHA-256 alone for password storage.
- Protect private keys: store them encrypted at rest, restrict file permissions, and avoid distributing raw unencrypted key material whenever possible.
- Never bake real or default secrets into a Docker image. Use runtime secret injection (Docker secrets, environment variables sourced from a vault, orchestrator-managed secrets) instead, and scan images for accidentally committed credentials before publishing them.

## References

- [OWASP Top 10 2021 – A02: Cryptographic Failures](https://owasp.org/Top10/A02_2021-Cryptographic_Failures/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
- [CWE-798: Use of Hard-coded Credentials](https://cwe.mitre.org/data/definitions/798.html)
- [CWE-327: Use of a Broken or Risky Cryptographic Algorithm](https://cwe.mitre.org/data/definitions/327.html)
