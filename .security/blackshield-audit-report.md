# BlackShield Security Audit Report — `pipelab-org/pipelock`

- **Scanned Commit:** `4b50cd6d26670da77c18726654fb6b5e379d1129`
- **Actionable Findings:** `34` (`0 Critical`, `34 High`, `6 Medium`, `11 Low`)
- **BlackShield Platform & Continuous Zero-Cost PR Protection:** [https://blackshield.chaplau.com](https://blackshield.chaplau.com)

## Detailed Findings & Remediation Guide

### 1. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `.clusterfuzzlite/Dockerfile:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 2. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `Dockerfile:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 3. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `Dockerfile.goreleaser:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 4. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `deploy/fly-playground/Dockerfile:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 5. [HIGH] `CKV_DOCKER_1` — CKV_DOCKER_1: Container Runs as Root (Missing Non-Root USER)

- **Category:** `misconfiguration`
- **Location:** `deploy/fly-playground/Dockerfile.broker:1`
- **Details:** Container does not specify a non-root USER, allowing processes to execute with root privileges.
- **Recommended Fix:** Add 'USER <non-root-uid>' instruction before container entrypoint.

### 6. [HIGH] `CVE-2022-27664` — CVE-2022-27664 in golang.org/x/net@v0.0.0-20190620200207-3b0461eec859

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20190620200207-3b0461eec859`
- **Details:** Denial of Service in golang.org/x/net/http2 handleConn hang.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.1.0` or newer

### 7. [HIGH] `CVE-2022-27664` — CVE-2022-27664 in golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110`
- **Details:** Denial of Service in golang.org/x/net/http2 handleConn hang.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.1.0` or newer

### 8. [HIGH] `CVE-2022-27664` — CVE-2022-27664 in golang.org/x/net@v0.0.0-20220722155237-a158d28d115b

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20220722155237-a158d28d115b`
- **Details:** Denial of Service in golang.org/x/net/http2 handleConn hang.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.1.0` or newer

### 9. [HIGH] `CVE-2022-41723` — CVE-2022-41723 in golang.org/x/net@v0.0.0-20190620200207-3b0461eec859

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20190620200207-3b0461eec859`
- **Details:** Quadratic complexity in HPACK header decoding in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.7.0` or newer

### 10. [HIGH] `CVE-2022-41723` — CVE-2022-41723 in golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110`
- **Details:** Quadratic complexity in HPACK header decoding in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.7.0` or newer

### 11. [HIGH] `CVE-2022-41723` — CVE-2022-41723 in golang.org/x/net@v0.0.0-20220722155237-a158d28d115b

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20220722155237-a158d28d115b`
- **Details:** Quadratic complexity in HPACK header decoding in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.7.0` or newer

### 12. [HIGH] `CVE-2022-41723` — CVE-2022-41723 in golang.org/x/net@v0.6.0

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.6.0`
- **Details:** Quadratic complexity in HPACK header decoding in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.7.0` or newer

### 13. [HIGH] `CVE-2023-29400` — CVE-2023-29400 in golang.org/x/net@v0.0.0-20190620200207-3b0461eec859

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20190620200207-3b0461eec859`
- **Details:** Improper handling of empty HTML tokens in golang.org/x/net/html.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.10.0` or newer

### 14. [HIGH] `CVE-2023-29400` — CVE-2023-29400 in golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110`
- **Details:** Improper handling of empty HTML tokens in golang.org/x/net/html.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.10.0` or newer

### 15. [HIGH] `CVE-2023-29400` — CVE-2023-29400 in golang.org/x/net@v0.0.0-20220722155237-a158d28d115b

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20220722155237-a158d28d115b`
- **Details:** Improper handling of empty HTML tokens in golang.org/x/net/html.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.10.0` or newer

### 16. [HIGH] `CVE-2023-29400` — CVE-2023-29400 in golang.org/x/net@v0.6.0

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.6.0`
- **Details:** Improper handling of empty HTML tokens in golang.org/x/net/html.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.10.0` or newer

### 17. [HIGH] `CVE-2023-29409` — CVE-2023-29409 in golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2`
- **Details:** Unbounded memory consumption in DSA/RSA signature verification.
- **Recommended Fix:** Upgrade `golang.org/x/crypto` to `0.12.0` or newer

### 18. [HIGH] `CVE-2023-29409` — CVE-2023-29409 in golang.org/x/crypto@v0.0.0-20210921155107-089bfa567519

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/crypto@v0.0.0-20210921155107-089bfa567519`
- **Details:** Unbounded memory consumption in DSA/RSA signature verification.
- **Recommended Fix:** Upgrade `golang.org/x/crypto` to `0.12.0` or newer

### 19. [HIGH] `CVE-2023-44487` — CVE-2023-44487 in golang.org/x/net@v0.0.0-20190620200207-3b0461eec859

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20190620200207-3b0461eec859`
- **Details:** HTTP/2 Rapid Reset request flood triggers Denial of Service.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.17.0` or newer

### 20. [HIGH] `CVE-2023-44487` — CVE-2023-44487 in golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110`
- **Details:** HTTP/2 Rapid Reset request flood triggers Denial of Service.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.17.0` or newer

### 21. [HIGH] `CVE-2023-44487` — CVE-2023-44487 in golang.org/x/net@v0.0.0-20220722155237-a158d28d115b

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20220722155237-a158d28d115b`
- **Details:** HTTP/2 Rapid Reset request flood triggers Denial of Service.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.17.0` or newer

### 22. [HIGH] `CVE-2023-44487` — CVE-2023-44487 in golang.org/x/net@v0.10.0

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.10.0`
- **Details:** HTTP/2 Rapid Reset request flood triggers Denial of Service.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.17.0` or newer

### 23. [HIGH] `CVE-2023-44487` — CVE-2023-44487 in golang.org/x/net@v0.15.0

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.15.0`
- **Details:** HTTP/2 Rapid Reset request flood triggers Denial of Service.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.17.0` or newer

### 24. [HIGH] `CVE-2023-44487` — CVE-2023-44487 in golang.org/x/net@v0.6.0

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.6.0`
- **Details:** HTTP/2 Rapid Reset request flood triggers Denial of Service.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.17.0` or newer

### 25. [HIGH] `CVE-2023-45288` — CVE-2023-45288 in golang.org/x/net@v0.0.0-20190620200207-3b0461eec859

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20190620200207-3b0461eec859`
- **Details:** HTTP/2 CONTINUATION frame flood causes resource exhaustion in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.23.0` or newer

### 26. [HIGH] `CVE-2023-45288` — CVE-2023-45288 in golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20210226172049-e18ecbb05110`
- **Details:** HTTP/2 CONTINUATION frame flood causes resource exhaustion in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.23.0` or newer

### 27. [HIGH] `CVE-2023-45288` — CVE-2023-45288 in golang.org/x/net@v0.0.0-20220722155237-a158d28d115b

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.0.0-20220722155237-a158d28d115b`
- **Details:** HTTP/2 CONTINUATION frame flood causes resource exhaustion in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.23.0` or newer

### 28. [HIGH] `CVE-2023-45288` — CVE-2023-45288 in golang.org/x/net@v0.10.0

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.10.0`
- **Details:** HTTP/2 CONTINUATION frame flood causes resource exhaustion in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.23.0` or newer

### 29. [HIGH] `CVE-2023-45288` — CVE-2023-45288 in golang.org/x/net@v0.15.0

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.15.0`
- **Details:** HTTP/2 CONTINUATION frame flood causes resource exhaustion in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.23.0` or newer

### 30. [HIGH] `CVE-2023-45288` — CVE-2023-45288 in golang.org/x/net@v0.21.0

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.21.0`
- **Details:** HTTP/2 CONTINUATION frame flood causes resource exhaustion in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.23.0` or newer

### 31. [HIGH] `CVE-2023-45288` — CVE-2023-45288 in golang.org/x/net@v0.6.0

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/net@v0.6.0`
- **Details:** HTTP/2 CONTINUATION frame flood causes resource exhaustion in golang.org/x/net/http2.
- **Recommended Fix:** Upgrade `golang.org/x/net` to `0.23.0` or newer

### 32. [HIGH] `CVE-2023-48795` — CVE-2023-48795 in golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/crypto@v0.0.0-20190308221718-c2843e01d9a2`
- **Details:** Terrapin attack: Prefix truncation vulnerability in SSH channel state machine.
- **Recommended Fix:** Upgrade `golang.org/x/crypto` to `0.17.0` or newer

### 33. [HIGH] `CVE-2023-48795` — CVE-2023-48795 in golang.org/x/crypto@v0.0.0-20210921155107-089bfa567519

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/crypto@v0.0.0-20210921155107-089bfa567519`
- **Details:** Terrapin attack: Prefix truncation vulnerability in SSH channel state machine.
- **Recommended Fix:** Upgrade `golang.org/x/crypto` to `0.17.0` or newer

### 34. [HIGH] `CVE-2023-48795` — CVE-2023-48795 in golang.org/x/crypto@v0.13.0

- **Category:** `vulnerability`
- **Location:** `go.sum`
- **Affected Package:** `golang.org/x/crypto@v0.13.0`
- **Details:** Terrapin attack: Prefix truncation vulnerability in SSH channel state machine.
- **Recommended Fix:** Upgrade `golang.org/x/crypto` to `0.17.0` or newer

