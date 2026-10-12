# Cryptographic Algorithm Report

What's actually in use, where, and why — as of the current code (`ca.py`, `tls_probe.py`,
`main.py`). This is the honest state, not the target state.

## 1. Root CA (`ca.py::ensure_root_ca`)

| Property | Value |
|---|---|
| Key type | EC, NIST P-384 (`SECP384R1`) |
| Signature | ECDSA-SHA384 |
| Lifetime | 10 years, generated once, stored locally |
| Purpose | Locally-trusted root, installed once into your browser/OS trust store, so the proxy can impersonate any site without a certificate warning |
| Quantum status | Classical. Low real-world urgency: the private key never leaves your machine or crosses the network, so it isn't exposed to "harvest now, decrypt later" traffic capture — that threat targets *recorded network traffic*, not local key material. |

## 2. Leaf certificates (`ca.py::get_leaf_cert`)

| Property | Value |
|---|---|
| Key type | EC, NIST P-256 (`SECP256R1`) |
| Signature | ECDSA-SHA256, signed by the root CA |
| Lifetime | 7 days, cached per hostname, regenerated if expired or signed by a stale CA |
| Purpose | What the proxy actually presents to the browser when impersonating `target_host` |
| Quantum status | Classical. |

## 3. Browser ↔ Proxy TLS — the client-facing relay leg

This is negotiated by Python's stdlib `ssl` module (`SSLContext(PROTOCOL_TLS_SERVER)`),
which is bound to **OpenSSL 3.0.15** on this machine.

- Modern browsers (Chrome, Firefox, Edge, Safari) have defaulted to *offering*
  `X25519MLKEM768` (hybrid post-quantum) since late 2024 — as of early 2026, roughly
  57% of browser-initiated TLS connections on the internet already include it.
- But OpenSSL 3.0.15 doesn't understand PQC groups at all (support starts at 3.2+), so no
  matter what the browser offers, our proxy can only ever pick a **classical** group back
  (X25519 or secp256r1), with AES-GCM or ChaCha20-Poly1305 as the symmetric cipher.
- **Quantum status: classical key exchange. This leg protects real traffic, and is not
  quantum-ready.**

## 4. Proxy ↔ Target TLS — the relay leg to the real site

Negotiated via `ssl.create_default_context()` — same OpenSSL 3.0.15 binding, same
limitation.

- Many real-world origins now prefer hybrid PQC when offered (Cloudflare defaults to
  `X25519MLKEM768` for both client-facing *and* origin connections where supported; Google
  Cloud begins defaulting to it in October 2026).
- Our proxy can't offer it, so even a fully PQC-capable target falls back to classical key
  exchange with us.
- **Quantum status: classical key exchange. This leg protects real traffic, and is not
  quantum-ready.**

## 5. The active PQC probe (`tls_probe.py`)

- Offers three groups: `x25519`, `secp256r1` (classical), and `X25519MLKEM768` (hybrid —
  ML-KEM-768 via `kyber-py`, a pure-Python implementation, combined with a real X25519
  share via `cryptography`).
- Reads only the plaintext ServerHello, then abandons the connection.
- **Quantum status: PQC-aware, but decorative. No application data is ever protected using
  this exchange — it exists purely to classify what the target supports.**

## Bottom line

| Leg | Key exchange in use | Protects real traffic? | Quantum-ready? |
|---|---|---|---|
| Root CA signing | ECDSA P-384 | n/a (signs certs, not traffic) | Classical |
| Leaf cert signing | ECDSA P-256 | n/a | Classical |
| Browser ↔ Proxy | X25519 / P-256 | **Yes** | **No** |
| Proxy ↔ Target | X25519 / P-256 | **Yes** | **No** |
| PQC probe | X25519 + ML-KEM-768 (hybrid) | No (throwaway) | Yes, but unused for real traffic |

**The proxy, as it stands, is not quantum-ready where it actually matters.** Only the
side-channel detector speaks PQC; the two connections that actually carry your browsing
traffic are 100% classical. That's the gap to close.
