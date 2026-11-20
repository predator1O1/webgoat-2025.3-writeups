# JWT Tokens — WebGoat

**Category:** A7 Identification and Authentication Failures
**Lesson:** JWT tokens
**Sub-assignments covered:** Decoding a JWT token, JWT signing, JWT cracking, Refreshing a token

## Objective

Work through four separate ways a JSON Web Token implementation can be abused when the server doesn't validate it carefully: reading a token's contents without a key, forging a token by abusing the `alg: none` algorithm, brute-forcing a weak HMAC signing secret offline, and replaying/tampering with a leaked, expired token to bypass both its signature and its expiry.

## Vulnerability

A JWT is just a base64url-encoded header + payload + signature — none of it is secret, and none of it is trustworthy unless the server verifies the signature against a secret/key it controls, enforces the expected algorithm, and rejects expired tokens. Each part of this lesson removes exactly one of those guarantees:

- **No signature verification needed to read it (CWE-347-adjacent):** the payload is plaintext once base64-decoded — nothing stops a client from reading claims it was never meant to see.
- **Algorithm confusion (`"alg":"none"`, CWE-347):** if the server's JWT library accepts an unsigned token when the header says so, an attacker can set the header to `{"alg":"none"}`, edit any claim (like `admin`), drop the signature entirely, and the server treats it as valid.
- **Weak HMAC secret (CWE-326 / CWE-521):** if the signing secret is weak enough to appear in a wordlist, it can be recovered offline by hashing candidate secrets against the real token and comparing signatures — no need to ever see the secret in transit.
- **Trusting client-supplied tokens from logs/leaks with no revocation (CWE-613):** a token that leaked (e.g. in a log file) stays valid until it expires — and if the server doesn't *also* reject whatever algorithm/expiry the attacker chooses, even an "expired" leaked token can be revived.

---

## Part 1 — Decoding a JWT Token

**Goal:** given an encoded token, find the username embedded in it — no cracking required, just decoding.

1. WebWolf's built-in **JWT** page decodes a token without needing the secret. Pasted the token given by the lesson in; it decoded cleanly:

   ```json
   // Header
   { "alg": "HS256" }

   // Payload
   {
     "authorities": [ "ROLE_ADMIN", "ROLE_USER" ],
     "client_id": "my-client-with-secret",
     "exp": 1607099608,
     "jti": "9bc92a44-0b1a-4c5e-be70-da52075b9a84",
     "scope": [ "read", "write" ],
     "user_name": "user"
   }
   ```

   (WebWolf correctly reports "Signature invalid" since no secret was supplied — that's expected; decoding the payload doesn't require it.)

   ![WebWolf decoding the original token](../assets/a7-identification-authentication-failures/jwt-tokens/01-webwolf-decode-original-token.png)

2. Submitted the username found in the payload (`user`) back into the lesson.

   ```json
   {"lessonCompleted":true,"feedback":"Congratulations. You have successfully completed the assignment."}
   ```

   ![Lesson completed — username recovered](../assets/a7-identification-authentication-failures/jwt-tokens/02-lesson-decoding-jwt-completed.png)

### Why It Worked

A JWT's header and payload are base64url, **not encryption** — anyone holding the token can read every claim inside it. The signature is the only thing protecting *integrity* (that the claims haven't been tampered with); it does nothing to keep the claims *confidential*. Any sensitive data should never be placed in a JWT payload in the first place.

---

## Part 2 — JWT Signing (`alg: none` Admin Bypass)

**Goal:** the lesson's voting feature only lets an **admin** reset vote counts. Starting as a normal logged-in user (`Tom`), become admin by forging the token, then reset the votes.

1. Lesson overview: a "Vote for your favorite" challenge board, logged in as `Tom`, with an explicit assignment to change the token and reset the votes once admin.

   ![JWT signing — lesson overview](../assets/a7-identification-authentication-failures/jwt-tokens/03-lesson-jwt-signing-votings-overview.png)

2. Captured the normal `GET /WebGoat/JWT/votings` request in Burp — this just lists the current vote counts using Tom's legitimate `access_token` cookie.

   ![Burp — normal votings request](../assets/a7-identification-authentication-failures/jwt-tokens/04-burp-repeater-get-votings.png)

3. Decoded Tom's actual cookie in WebWolf: signed with `HS256`/`HS512`, payload shows `"admin":"false"`.

   ![Tom's legitimate token — admin: false](../assets/a7-identification-authentication-failures/jwt-tokens/05-webwolf-decode-tom-legit-token.png)

4. Built a forged token by hand: kept the payload but set `"admin":"true"`, and — critically — changed the header to `{"alg":"none"}` and removed the signature entirely (a JWT with `alg: none` just ends in a trailing `.` with nothing after it).

   ![Forged token — alg: none, admin: true](../assets/a7-identification-authentication-failures/jwt-tokens/06-webwolf-forged-alg-none-admin-true.png)

5. First attempt: resent the vote-reset request with Tom's **original, unmodified** token (no forgery yet) as a baseline — rejected, confirming a normal user genuinely cannot reset votes:

   ```json
   {"lessonCompleted":false,"feedback":"Only an admin user can reset the votes"}
   ```

   ![Burp HTTP history — unmodified token correctly rejected](../assets/a7-identification-authentication-failures/jwt-tokens/07-burp-history-first-attempt-rejected.png)

6. Replayed the same request, this time with the **forged `alg: none` / `admin: true`** token set as the `access_token` cookie:

   ```json
   {"lessonCompleted":true,"feedback":"Congratulations. You have successfully completed the assignment."}
   ```

   ![Burp Repeater — forged token accepted, votes reset](../assets/a7-identification-authentication-failures/jwt-tokens/08-burp-repeater-alg-none-votes-reset-success.png)

### Why It Worked

The JWT spec allows `"alg":"none"` as a legitimate (if dangerous) option, meant only for cases where a token's integrity is already guaranteed some other way. Several JWT libraries historically honored whatever `alg` the token's own header claimed, instead of only trusting an algorithm the *server* expects — so an attacker can simply tell the library "this token isn't signed" and the library takes the unsigned claims at face value. Since no cryptographic check ever runs, any claim (like `admin`) can be set to whatever the attacker wants.

---

## Part 3 — JWT Cracking (Weak HMAC Secret)

**Goal:** given a legitimately-signed token, recover the HMAC secret key offline via wordlist attack, then forge a *new*, properly-signed token with the username changed to `WebGoat`.

1. Lesson overview — a token is provided; the assignment is to find the signing secret and submit a new, validly-signed token with `username` changed to `WebGoat`.

   ![JWT cracking — lesson overview](../assets/a7-identification-authentication-failures/jwt-tokens/09-lesson-jwt-cracking-overview.png)

2. Rather than using a generic tool, I wrote and ran my own JWT HMAC secret-verification script (**[JWT-HMAC-Auditor](https://github.com/predator1O1/JWT-HMAC-Auditor)**), which recomputes the `HS256` signature for each candidate secret in a wordlist and compares it against the token's actual signature:

   ```bash
   python3 brute-force-secret-key-jwt.py -t "<token>" -w wordlist-cracker-secret-key-jwt
   ```

   Output:

   ```
   [*] JWT HMAC Secret Verification
   [*] Algorithm: HS256
   [*] Threads: 10
   [*] Candidates: 9894
   [*] Starting verification...

   [+] MATCH FOUND!
   [+] Secret: victory
   [+] Payload: {
     "iss": "WebGoat Token Builder",
     "aud": "webgoat.org",
     "iat": 1794656360,
     "exp": 1794656420,
     "sub": "tom@webgoat.org",
     "username": "Tom",
     "Email": "tom@webgoat.org",
     "Role": [ "Manager", "Project Administrator" ]
   }
   [*] Verification completed: matching secret found.
   ```

   ![Kali — secret key cracked via wordlist](../assets/a7-identification-authentication-failures/jwt-tokens/10-kali-brute-force-secret-key-found.png)

3. With the secret (`victory`) in hand, edited the payload's `username` from `Tom` to `WebGoat`, kept everything else, and re-signed the token in WebWolf using that secret as the signing key:

   ```json
   {
     "iss": "WebGoat Token Builder",
     "aud": "webgoat.org",
     ...
     "username": "WebGoat"
   }
   ```

   WebWolf confirmed: **Signature valid.**

   ![WebWolf — re-signed forged token, signature valid](../assets/a7-identification-authentication-failures/jwt-tokens/11-webwolf-forged-token-signature-valid.png)

4. Submitted the newly-signed token into the lesson's flag field.

   ```
   Congratulations. You have successfully completed the assignment.
   ```

   ![Lesson completed — JWT cracking](../assets/a7-identification-authentication-failures/jwt-tokens/12-lesson-jwt-cracking-completed.png)

### Why It Worked

HMAC-signed JWTs are only as strong as the shared secret. If that secret is short, guessable, or drawn from a common wordlist, an attacker with just one valid token (no server access needed) can brute-force it entirely offline — try a candidate secret, compute `HMAC-SHA256(header.payload, candidate)`, and check if it matches the token's actual signature. Once the secret is recovered, the attacker can sign **any** payload they like, and the server will accept it as fully legitimate, because cryptographically it *is* legitimate — just not from the party the server thinks it is.

**Solution reference:** the cracking script used here is published at **[github.com/predator1O1/JWT-HMAC-Auditor](https://github.com/predator1O1/JWT-HMAC-Auditor)**.

---

## Part 4 — Refreshing a Token (Leaked Token + Expiry Bypass)

**Goal:** modeled on a real private Bugcrowd bug-bounty report. A breached logfile contains a request with another user's (`Tom`'s) JWT. Use it to order books but have **Tom** pay for them — without ever having Tom's real, current session.

1. Lesson overview — a shopping cart with two books already added, a "Checkout" flow, and the challenge: make Tom pay for this order using only what a leaked logfile reveals.

   ![Refreshing a token — cart overview](../assets/a7-identification-authentication-failures/jwt-tokens/13-lesson-refreshing-token-cart-overview.png)

2. The lesson links to a leaked server logfile (`logs.txt`). Opening it directly revealed an old request carrying Tom's token as a URL query parameter:

   ```
   GET /JWT/refresh/checkout?token=eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1MjYxMzE0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iOiJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQkyDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4QuqmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q HTTP/1.1" 401
   ```

   ![Leaked logfile containing Tom's old token](../assets/a7-identification-authentication-failures/jwt-tokens/14-leaked-logfile-tom-token.png)

3. Decoded the leaked token in WebWolf:

   ```json
   // Header: {"alg":"HS512"}
   // Payload:
   { "admin": "false", "exp": 1526217811, "iat": 1526131411, "user": "Tom" }
   ```

   `exp: 1526217811` converts to **13 May 2018** — the token expired years ago, which is exactly why the logged request above got a `401`.

   ![Decoding the leaked token — expired](../assets/a7-identification-authentication-failures/jwt-tokens/15-webwolf-decode-leaked-token-expired.png)

4. Converted the Unix timestamp to a human date to confirm the expiry, then picked a far-future date and converted *that* back to a Unix timestamp to use as a replacement `exp`:

   ```
   1526217811 → 13 May 2018 (expired)
   13 May 2027 → 1810195411 (new exp to use)
   ```

   ![Working out the replacement expiry timestamp](../assets/a7-identification-authentication-failures/jwt-tokens/16-timestamp-conversion-notes.png)

5. Forged a new token from the leaked payload: set `alg` to `none`, bumped `exp` to `1810195411`, left `user: Tom` and `admin: false` as-is, and dropped the signature.

   ![Forged alg:none token with extended expiry](../assets/a7-identification-authentication-failures/jwt-tokens/17-webwolf-forged-alg-none-extended-exp.png)

6. Sent `POST /WebGoat/JWT/refresh/checkout` with this forged token as the `Authorization: Bearer` header. The server accepted the unsigned token (same `alg: none` weakness as Part 2) and let the checkout proceed as Tom — but responded with a nudge rather than full credit:

   ```json
   {
     "lessonCompleted": true,
     "feedback": "Nicely found! You solved the assignment with 'alg: none' can you also solve it by using the refresh token?"
   }
   ```

   ![Burp — alg:none checkout succeeds, hints at refresh-token path](../assets/a7-identification-authentication-failures/jwt-tokens/18-burp-repeater-alg-none-checkout-partial-success.png)

7. Followed that hint: rather than only forging an unsigned token, used the lesson's own **refresh** flow — decoding showed the same claims still signed as `HS512`, with the extended expiry now baked into a token obtained through the legitimate refresh mechanism rather than just stripped of its signature.

   ![Decoded HS512 token with extended expiry via refresh flow](../assets/a7-identification-authentication-failures/jwt-tokens/19-webwolf-decode-hs512-extended-exp-token.png)

8. Resent `POST /WebGoat/JWT/refresh/checkout` using that refreshed token as the Bearer token:

   ```json
   {"lessonCompleted":true,"feedback":"Congratulations. You have successfully completed the assignment."}
   ```

   ![Burp Repeater — refresh-token path fully solves the assignment](../assets/a7-identification-authentication-failures/jwt-tokens/20-burp-repeater-refresh-checkout-success.png)

### Why It Worked

Two separate failures compound here:

- **No revocation / rotation for leaked tokens.** A token that ends up in a logfile (or any other leak) is just a bearer credential — anyone holding it can use it until it expires, with no way for the server to invalidate that *specific* token early.
- **`exp` is just another client-editable claim if `alg: none` is accepted.** Even an expired, leaked token becomes dangerous again if the server will accept an unsigned replacement — the attacker doesn't need to forge a *new* identity, just extend the lifetime of someone else's.
- **The refresh endpoint itself didn't tie the new token tightly enough to proof of the original session being legitimate**, so a token obtained through "refreshing" an old/leaked credential carried forward the same impersonation.

## Remediation

- **Never trust the `alg` field from the token itself.** The server must hardcode which algorithm(s) it accepts (e.g. always verify as `HS256` with its own key) and reject anything else outright — including `none` — rather than asking the token "how should I verify you?"
- **Use a long, high-entropy, randomly generated signing secret** (or asymmetric keys, `RS256`/`ES256`, where only the server holds the private key) — never a dictionary word or anything a wordlist attack could recover in seconds.
- **Keep sensitive data out of JWT payloads.** Since the payload is only base64, not encrypted, anything that shouldn't be world-readable (internal roles, emails, IDs) needs either server-side session state instead, or a token format that's actually encrypted (e.g. JWE).
- **Enforce `exp` (and `iat`) strictly server-side**, and treat a token nearing/at expiry as fully invalid — never accept a client-supplied extension to its own lifetime.
- **Treat leaked tokens as compromised credentials.** Short token lifetimes plus a real revocation/deny-list mechanism (or rotating signing keys) limit how much damage a token found in a log, browser history, or intercepted request can do.
- **Don't log tokens or other bearer credentials** in access logs, URLs, or anywhere else they might be captured and later leaked — the entire chain in Part 4 started from a token that should never have appeared in a logfile in the first place.

## References

- [OWASP – JSON Web Token (JWT) Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/JSON_Web_Token_for_Java_Cheat_Sheet.html)
- [Auth0 – Critical vulnerabilities in JSON Web Token libraries](https://auth0.com/blog/critical-vulnerabilities-in-json-web-token-libraries/)
- [OWASP – Improper Authentication (CWE-287)](https://cwe.mitre.org/data/definitions/287.html)
- [CWE-613 – Insufficient Session Expiration](https://cwe.mitre.org/data/definitions/613.html)
- Solution reference (secret-key cracking tool, author's own): [github.com/predator1O1/JWT-HMAC-Auditor](https://github.com/predator1O1/JWT-HMAC-Auditor)
