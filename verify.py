#!/usr/bin/env python3
"""
Verify a download using RFC 9530 Content-Digest headers.

Usage:
    python3 verify.py https://example.com/files/archive.tar.gz
"""

import hashlib, base64, re, sys, urllib.request

# The algorithms we know how to verify
ALGORITHMS = {
    "sha-256": hashlib.sha256,
    "sha-512": hashlib.sha512,
}

def parse_content_digest(header):
    """
    Parse an RFC 9530 Content-Digest header value.
    Input:  'sha-256=:G/o0dKAIkb7PjiuLO7pdoePtJdpR5qCZiOcsznTB11g=:'
    Output: ('sha-256', b'\x1b\xfa\x34\x74...')  (algorithm name, raw hash bytes)
    """
    m = re.match(r'(sha-(?:256|512))=:([A-Za-z0-9+/=]+):', header)
    if not m:
        return None, None
    return m.group(1), base64.b64decode(m.group(2))

if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <url>")
    sys.exit(1)

# Step 1: Download the file and grab the Content-Digest header
url = sys.argv[1]
print(f"Fetching {url} ...")

req = urllib.request.Request(url)
with urllib.request.urlopen(req) as resp:
    body = resp.read()
    header = resp.getheader("Content-Digest")

if not header:
    print("No Content-Digest header in response.")
    print("(Server may not have a sidecar checksum for this file.)")
    sys.exit(1)

print(f"Content-Digest: {header}")

# Step 2: Parse the header to get the algorithm and the expected hash
algo_name, expected = parse_content_digest(header)
if not algo_name:
    print(f"Could not parse header: {header}")
    sys.exit(1)

# Step 3: Hash the bytes we actually received
actual = ALGORITHMS[algo_name](body).digest()

# Step 4: Compare
print(f"\n  Algorithm : {algo_name}")
print(f"  Expected  : {expected.hex()}")
print(f"  Got       : {actual.hex()}\n")

if actual == expected:
    print("MATCH -- file integrity verified.")
else:
    print("MISMATCH -- file may be corrupted or tampered with.")
    sys.exit(1)
