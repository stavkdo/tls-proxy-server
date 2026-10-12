# System Flow

This reflects what's actually implemented right now (`main.py`, `ca.py`, `tls_probe.py` +
`tests/`). Pieces we've discussed but haven't built yet (policy engine, warning interstitial,
dashboard, persistence) are marked *(planned)* and shown dashed.

## 1. Components

```mermaid
flowchart LR
    Browser["Browser\n(points its proxy\nsettings at :4443)"]

    subgraph Proxy["Proxy process (main.py)"]
        Handle["handle_client()\nper-connection coroutine"]
        Relay["process_ssl_stream()\nfull-duplex decrypt/relay"]
    end

    CA["ca.py\nRoot CA + per-hostname\nleaf cert cache"]
    Probe["tls_probe.py\nhand-built ClientHello/\nServerHello, group classifier"]
    Target["Real target site"]

    Dash1["Policy engine (planned)"]
    Dash2["Warning page (planned)"]
    Dash3["Event log + DB (planned)"]
    Dash4["Dashboard (planned)"]

    Browser -- "CONNECT host:port" --> Handle
    Handle -- "get_leaf_cert(hostname)" --> CA
    Handle -- "probe(host, port)" --> Probe
    Probe -. "crafted ClientHello" .-> Target
    Handle -- "real TLS connect" --> Target
    Handle --> Relay
    Relay <-- "decrypted traffic" --> Browser
    Relay <-- "re-encrypted traffic" --> Target

    Handle -.-> Dash1
    Dash1 -.-> Dash2
    Handle -.-> Dash3
    Dash3 -.-> Dash4

    style Dash1 stroke-dasharray: 5 5
    style Dash2 stroke-dasharray: 5 5
    style Dash3 stroke-dasharray: 5 5
    style Dash4 stroke-dasharray: 5 5
```

## 2. Per-connection sequence (what happens for one site the browser visits)

```mermaid
sequenceDiagram
    participant B as Browser
    participant P as Proxy (handle_client)
    participant C as ca.py
    participant Pr as tls_probe.py
    participant T as Target site

    B->>P: CONNECT example.com:443
    P->>P: parse target_host, target_port

    Note over P,T: PQC probe -- separate, throwaway connection
    P->>Pr: probe(target_host, target_port)
    Pr->>T: crafted ClientHello (classical + hybrid-PQC groups offered)
    T-->>Pr: ServerHello (plaintext -- group selection visible here)
    Pr->>Pr: classify selected group (classical / hybrid-pqc / unknown)
    Pr-->>P: ProbeResult
    P->>P: print [PQC] classification

    Note over P,T: Real relay connection (separate from the probe)
    P->>T: TCP connect
    P-->>B: HTTP/1.1 200 Connection Established

    Note over P,C: Client-facing TLS -- proxy impersonates target_host
    P->>C: get_leaf_cert(target_host)
    C-->>P: leaf cert signed by local root CA (cached or freshly minted)
    B->>P: TLS ClientHello (SNI = example.com)
    P->>P: sni_callback mints/reuses cert for that hostname
    P-->>B: ServerHello + cert (browser trusts it via installed root CA)

    Note over P,T: Proxy-to-target TLS -- normal validated TLS
    P->>T: TLS ClientHello
    T-->>P: ServerHello + real cert (validated via ssl.create_default_context)

    Note over B,T: Both handshakes complete -- full-duplex relay begins
    loop until either side closes
        B->>P: encrypted bytes
        P->>P: decrypt (client sslobj) -> plaintext -> re-encrypt (target sslobj)
        P->>T: encrypted bytes
        T->>P: encrypted bytes
        P->>P: decrypt (target sslobj) -> plaintext -> re-encrypt (client sslobj)
        P->>B: encrypted bytes
    end
```

## 3. Dynamic certificate selection (`build_client_ssl_context`)

```mermaid
flowchart TD
    Start["Client TLS handshake begins"] --> SNI{"Did the browser\nsend SNI?"}
    SNI -- "yes" --> UseSNI["hostname = SNI value"]
    SNI -- "no" --> UseDefault["hostname = target_host\nfrom the CONNECT line"]
    UseSNI --> Lookup
    UseDefault --> Lookup["ca.get_leaf_cert(hostname, ca_key, ca_cert)"]
    Lookup --> MemCache{"In-memory cache hit\nfor (hostname, ca_fingerprint)?"}
    MemCache -- "yes" --> Serve["Load that cert into a\nfresh per-host SSLContext"]
    MemCache -- "no" --> DiskCache{"On-disk cert exists,\nnot expired, AND signed\nby the current CA?"}
    DiskCache -- "yes" --> Serve
    DiskCache -- "no" --> Generate["Generate new EC leaf key,\nsign with root CA,\nwrite to cache"]
    Generate --> Serve
    Serve --> Present["sslobj.context = per-host context\n(cert presented to browser)"]
```

## 4. PQC group detection (`tls_probe.probe`)

```mermaid
flowchart TD
    A["build_client_hello(hostname)"] --> B["Offer groups:\nx25519, secp256r1 (classical)\nX25519MLKEM768 (hybrid-pqc)"]
    B --> C["Real key material per group:\ncryptography (EC/X25519)\nkyber-py (ML-KEM-768)"]
    C --> D["Send raw ClientHello\nover a plain TCP socket"]
    D --> E{"First record type?"}
    E -- "Alert" --> F["ProbeResult(error=...)"]
    E -- "Handshake" --> G["Accumulate until full\nServerHello received"]
    G --> H["Read selected cipher suite\n+ key_share group ID\n(sent in plaintext)"]
    H --> I["classify_group(group_id)"]
    I --> J["ProbeResult:\nclassical / hybrid-pqc / unknown"]

    style F fill:#3a1f1f
```

## Known limitation (by design, for now)

The probe offers PQC groups, but the *real relay connection* to the target (step in section 2)
still uses plain stdlib `ssl` (classical only) — it only needs to work, not to detect anything.
Only the throwaway probe connection tests PQC support. Also: since this machine's OpenSSL is
3.0.15, our own probe's classical groups are real, but a target that *only* speaks TLS 1.2 or
earlier will simply fail our TLS-1.3-only probe with a handshake alert rather than being
misclassified — this shows up as `error`, not a false "classical" result.
