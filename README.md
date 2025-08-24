# navFHE_rs — Privacy-Preserving Drone Collision Avoidance (Rust)

A Rust implementation of encrypted path comparison for drone collision avoidance based on the paper "Privacy-Preserving Drone Navigation Through Homomorphic Encryption for Collision Avoidance" presented at IEE LCN conference (2024 https://arxiv.org/pdf/2507.14713). Two parties (“Alice” and “Bob”) determine whether their flight segments intersect **without revealing** their underlying paths to each other. The design follows the LCN’24 paper’s protocol, assumptions, and evaluation approach, with a faithful translation of the line-segment intersection algorithm (Algorithm 2) into encrypted operations.&#x20;

## Contents

* [Motivation & Overview](#motivation--overview)
* [System & Threat Model](#system--threat-model)
* [Cryptographic Building Blocks](#cryptographic-building-blocks)
* [Encrypted Intersection Algorithm](#encrypted-intersection-algorithm)
* [Implementation Layout (Rust Crates)](#implementation-layout-rust-crates)
* [Correctness & Tests](#correctness--tests)
* [Performance & Experiment Plan](#performance--experiment-plan)
* [Running the Demo](#running-the-demo)
* [Wire Messages & Serde](#wire-messages--serde)
* [Security Considerations](#security-considerations)
* [Roadmap](#roadmap)
* [Citations](#citations)

---

## Motivation & Overview

Sharing detailed flight paths leaks business-sensitive info (destinations, customer patterns). Our protocol lets two operators learn **only** whether their paths intersect; if so, Alice temporarily changes altitude to avoid collision (Bob learns nothing). We operate on 2D paths (X,Y); altitude is used only for *resolution* of a detected conflict.&#x20;

---

## System & Threat Model

* **Roles**: Bob holds a public/secret key and an encrypted route; Alice encrypts her route under Bob’s public key and executes the protocol. Results (intersect / not) are revealed only to Alice; roles can be swapped to inform Bob too.&#x20;
* **Assumptions**: Honest-but-curious parties; wide-area comms possible (e.g., NB-IoT/LoRa) to query other nearby drones; default altitude per regulation; 2D planar paths for geometry.&#x20;
* **Threats considered**: “Brute-force probing” by scanning many small parallel segments to reconstruct a route; mitigations include protocol time windows, rate limits, bandwidth constraints, and path/result minimality.&#x20;

---

## Cryptographic Building Blocks

* **Additively homomorphic encryption** (Paillier) for ciphertext addition and plaintext scaling; used throughout for sums and differences.&#x20;
* **Blinded ct×ct multiply via two-party offload**: Alice blinds `JxK, JyK` with **fresh, uniform Zₙ** randomizers `a,b`, asks Bob to multiply blinded values, then unblinds:

  $$
  JxyK = J(x{+}a)(y{+}b)K \;\oplus\; J{-}bxK \;\oplus\; J{-}ayK \;\oplus\; J{-}abK
  $$

  This is Eq. (3) in the paper and is **enforced** in code by a single helper (Rust: `mul_ct_ct`) and a test-only guard that panics on any raw multiply path.&#x20;
* **Encrypted integer comparison**: Joye–Salehi comparison protocol used to obtain encrypted bits for `<, =, >` relative to zero (via a “centered” representative in $(-n/2,n/2]$). In Rust, our comparator API returns `(lt, eq, gt)` ciphertext bits.&#x20;

---

## Encrypted Intersection Algorithm

We implement the classic segment intersection test (Cormen et al.) in encrypted form (Algorithm 2 in the paper):

1. Compute orientations
   $\Delta_1 = \text{orient}(A,B,C)$, $\Delta_2 = \text{orient}(A,B,D)$,
   $\Delta_3 = \text{orient}(C,D,A)$, $\Delta_4 = \text{orient}(C,D,B)$, where
   $\text{orient}(P,Q,R) = (Q_y{-}P_y)(R_x{-}Q_x) - (Q_x{-}P_x)(R_y{-}Q_y)$.
2. If signs of $\Delta_1,\Delta_2$ are opposite **and** signs of $\Delta_3,\Delta_4$ are opposite → **intersect**.
3. Otherwise, if collinear (all zeros), run encrypted **on-segment** checks (axis-aligned bounding-box test) for each endpoint.

Our Rust code mirrors this exactly:

* **Products** use only `mul_ct_ct` with fresh uniform Zₙ blinders.
* **On-segment** implements `min`/`max` via encrypted `select`, and interval tests with `≥` and `≤` derived from `(lt,eq,gt)` bits.
* AABB prefilter is available as a fast encrypted rejector.
  All steps align to Algorithm 2 and the paper’s Section “Computing Intersections.”&#x20;

---

## Implementation Layout (Rust Crates)

This workspace structure extends the original scaffold and clarifies roles:&#x20;

```
hpcomp-rust/
  hpcompcrypto   # crypto traits + Paillier/DGK interfaces; Joye compare params
  hpcompalgo     # encrypted geometry (orient, on-segment), mul_ct_ct helper
  hpcompproto    # wire types; versioned JoyeParams serde wrapper (t, slack)
  hpcompnode     # binaries: alice (initiator), bob (responder), cleartext demo
  hpcompsim      # load/simulation harness (TBD for n>2 drones/satellites)
```

Notes:

* **`mul_ct_ct`** wraps Eq.(3) and is the **only** place that calls `RemoteMultiplier::mult_batch`; tests guard this invariant.
* **`JoyeParams`** currently has fields `{ t: u32, slack: u32 }`; `hpcompproto` ships a **versioned** byte codec (`JOYEPARAMS|v=1|t|slack`).
* The top-level README’s original quick-start is still valid; we’ve expanded it below.&#x20;

---

## Correctness & Tests

* Plaintext baseline (`orient_plain`, `onseg_plain`) matches the encrypted algorithm decision logic exactly (deterministic orientation; collinear fallback).
* Unit tests exercise:

  * sign comparison around zero (centered domain)
  * random segment pairs parity (encrypted vs. plain)
  * collinear overlap/touch edge cases
  * AABB parity
* A test-only guard (`GuardedMult`) ensures **every** ct×ct multiply goes through `mul_ct_ct` with fresh uniform Zₙ blinders. Failures print centered deltas and on-segment flags to triage.

---

## Performance & Experiment Plan

**Paper baseline**: The paper’s Java prototype used 2048-bit keys, 30 random single-segment trials on Debian 12 VMs (2 vCPU / 4 GB) to emulate constrained hardware. Results show \~**30% latency reduction** and significantly less network traffic than Li et al. (garbled circuits), and faster than Desai et al. (grid-MPC) on Raspberry Pi 4.&#x20;

**Efficiency plan** (to replicate & extend):

1. **Bench harness**: add `criterion` benches for `orient`, `on_segment`, and full `segments_intersect`.
2. **Profiles**: (a) laptop dev, (b) VM (2 vCPU/4 GB), (c) Raspberry Pi 4.
3. **Parameters**: 2048-bit Paillier, Joye compare with `{ t: 31..64, slack: 32..64 }`.
4. **Metrics**: wall-clock time per compare; bytes written per protocol role.
5. **Data set**: 30 random pairs in $[-99,99]^2$ (single-segment parity to match paper).
6. **Reporting**: CSV + plots; compare against paper numbers (noting Java↔Rust/runtime differences).&#x20;

---

## Running the Demo

### Prereqs

* Rust 1.74+ recommended
* Linux/macOS (Windows should work via WSL)
* OpenSSL/Rustls as required by QUIC stack

Build:

```bash
cargo build
```

Unit tests:

```bash
cargo test -p hpcompcrypto
cargo test -p hpcompalgo
cargo test -p hpcompproto
cargo test -p hpcompnode
```

Cleartext baseline:

```bash
cargo run -p hpcompnode --bin cleartext -- examples/path_a.json examples/path_b.json
```

### Generate keys

```bash
# Bob keys (used for route encryption and protocol)
cargo run -p hpcompcrypto --bin keygen-paillier -- --out ./keys-bob --bits 2048

# Alice keys (used only for masked-reveal decryption)
cargo run -p hpcompcrypto --bin keygen-paillier -- --out ./keys-alice --bits 2048

# (Optional) record Bob’s key hash for pinning
cargo run -p hpcompcrypto --bin verify-keys -- --paillier-pub ./keys-bob/paillier_pub.json
```

Two-party run (loopback):

```bash
# Terminal 1 (Bob)
cargo run -p hpcompnode --bin bob -- \
  --path ./examples/path_b.json \
  --cert-out ./bob_cert.der \
  --paillier-pub ./keys-bob/paillier_pub.json \
  --paillier-priv ./keys-bob/paillier_priv.json \
  --bob-pk-hash-out ./keys-bob/pk_hash.txt \
  --listen 127.0.0.1:45555
```

```bash
# Terminal 2 (Alice)
cargo run -p hpcompnode --bin alice -- \
  --path ./examples/path_a.json \
  --peer 127.0.0.1:45555 \
  --bob-cert ./bob_cert.der \
  --paillier-pub ./keys-bob/paillier_pub.json \
  --alice-priv ./keys-alice/paillier_priv.json \
  --prefilter off \
  --expect-bob-key-hash <bob_pk_sha256>
```

---

## Wire Messages & Serde

* `hpcompproto` uses an **opaque**, versioned codec for `JoyeParams` (currently just `{t, slack}`) to avoid placing serde derives in `hpcompcrypto`. The adapter is implemented with `#[serde(with = "joye_params_v1")]`, encoding as:

  ```
  b"JOYEPARAMS" || u32(version=1) || u32(t) || u32(slack)
  ```

* This keeps the wire stable as fields evolve (bump the version and extend the decoder).

---

## Security Considerations

* **Privacy**: Paths remain encrypted; only a boolean intersection result is disclosed to the initiator. Bob learns nothing unless roles are swapped.&#x20;

* **Correctness under blinding**: All ct×ct products use fresh, uniform Zₙ masks; Eq.(3) unblinding uses the 4-term correction exactly. Tests enforce this property.&#x20;

* **Probe resistance**: The “parallel-line brute-force” reconstruction is curtailed by time windows, bandwidth limits, default altitudes, and rate limiting; practical feasibility is low per paper’s discussion. We recommend:

  * rate limits & per-peer quotas
  * minimum segment length and path sanity checks
  * optional noise / padding in message sizes and response timing
  * audit hooks for repeated adversarial querying patterns


* **Side channels**: avoid branch-dependent early returns visible on the wire; keep constant message shapes across positive/negative results when possible.

---

## Roadmap

* **Crypto**: Harden Paillier backend; add DGK for comparisons (paper used Joye–Salehi; we abstract comparator, so drop-in is easy).&#x20;
* **Transport**: QUIC/TLS transport wrappers; padding & batching.
* **Bench parity**: Publish Rust numbers alongside the paper’s Java results; stress at larger path counts.
* **Multi-party**: Extend to >2 drones (pairwise compare within time window, deterministic tie-breakers for altitude changes).

---



