# mod_digest_fields

An Apache module that adds [RFC 9530](https://datatracker.ietf.org/doc/html/rfc9530) `Content-Digest` and `Repr-Digest` headers to HTTP responses, enabling clients to verify file integrity without a separate request.

When Apache serves a file, the module checks for a sidecar checksum file alongside it. If one exists, the hash is included in the response header using the standard Digest Fields format.

```
GET /releases/myapp-2.1.tar.gz HTTP/1.1

HTTP/1.1 200 OK
Content-Digest: sha-256=:VnYLtiDf1sVMSehoMeoYSw0u0cHNKh7A+4XSmaGSpEc=:
Content-Length: 10485760
```

The client now has a cryptographic hash of the file before it even finishes downloading.

## Live Example

[https://www.any53.com/](https://www.any53.com/) uses this module in production.

## See It Work

### Server side: publish a file with its checksum

```bash
# Create a file to serve
echo "Hello, RFC 9530!" > /var/www/files/greeting.txt

# Create the sidecar checksum (one command)
sha256sum /var/www/files/greeting.txt > /var/www/files/greeting.txt.sha256

# That's it. The sidecar file looks like this:
cat /var/www/files/greeting.txt.sha256
# 1bfa3474a00891becf8e2b8b3bba5da1e3ed25da51e6a09988e72cce74c1d758  /var/www/files/greeting.txt
```

Add two lines to your Apache config:

```apache
<Directory "/var/www/files">
    DigestFields On
</Directory>
```

Reload Apache, then request the file:

```
$ curl -si http://localhost/files/greeting.txt

HTTP/1.1 200 OK
Content-Digest: sha-256=:G/o0dKAIkb7PjiuLO7pdoePtJdpR5qCZiOcsznTB11g=:
Content-Length: 18
Content-Type: text/plain

Hello, RFC 9530!
```

The `Content-Digest` header is the SHA-256 hash of the file, base64-encoded per [RFC 8941 Structured Fields](https://datatracker.ietf.org/doc/html/rfc8941).

### Client side: verify the download

A [verify.py](verify.py) script is included that downloads a file and checks it against the `Content-Digest` header in one step:

```
$ python3 verify.py http://localhost/files/greeting.txt
Fetching http://localhost/files/greeting.txt ...
Content-Digest: sha-256=:G/o0dKAIkb7PjiuLO7pdoePtJdpR5qCZiOcsznTB11g=:

  Algorithm : sha-256
  Expected  : 1bfa3474a00891becf8e2b8b3bba5da1e3ed25da51e6a09988e72cce74c1d758
  Got       : 1bfa3474a00891becf8e2b8b3bba5da1e3ed25da51e6a09988e72cce74c1d758

MATCH -- file integrity verified.
```

The script does exactly what a client should do:

1. Download the file and read the `Content-Digest` header
2. Parse the algorithm name and base64-encoded hash from the header
3. Hash the downloaded bytes with the same algorithm
4. Compare the two -- if they match, the file is intact

No dependencies beyond Python 3. Here's the full script ([verify.py](verify.py)):

```python
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
```

### Compressed files: both headers at once

For mirror servers hosting pre-compressed archives, the module can emit both headers -- one for the compressed file on disk, and one for the uncompressed original:

```bash
# On the server
sha256sum archive.tar.gz  > archive.tar.gz.sha256   # hash of compressed file
sha256sum archive.tar     > archive.tar.sha256       # hash of original
```

```apache
<Directory "/var/www/mirror">
    DigestFields On
    DigestFieldsRepr On
    SetEnv no-gzip 1
</Directory>
```

```
$ curl -si http://localhost/mirror/archive.tar.gz

HTTP/1.1 200 OK
Content-Digest: sha-256=:kF3mVaSgX1OwBxHj6qMKQRjOCPRtkHmP7mNJKAergNQ=:
Repr-Digest: sha-256=:G/o0dKAIkb7PjiuLO7pdoePtJdpR5qCZiOcsznTB11g=:
```

- `Content-Digest` = hash of `archive.tar.gz` (the bytes on the wire)
- `Repr-Digest` = hash of `archive.tar` (the uncompressed representation)

## How It Works

The module uses **sidecar files** -- small text files containing a checksum, stored next to the content they describe:

```
/var/www/files/
    data.json               <- the file Apache serves
    data.json.sha256        <- the sidecar (contains the SHA-256 hash)
```

When a request arrives for `data.json`, the module:

1. **Fixup phase**: Checks if `data.json.sha256` exists, reads and parses the hex hash, converts to base64 per RFC 8941, and stashes the result in request notes
2. **Output filter phase**: Runs after mod_deflate/mod_brotli. Checks `Content-Encoding` to pick the correct header:
   - No compression: emits `Content-Digest` (hash matches bytes on the wire)
   - Compressed (gzip/br): emits `Repr-Digest` (hash is of the representation before encoding)

If no sidecar exists, no header is added. No errors, no noise.

### Sidecar file format

The module accepts common checksum formats. Any of these work:

```
# Plain hash
5676bbb620dfd6c54c49e86831ea2577aa8d9cbc7e6ad5ea1f6848e9bc4f69fa

# GNU coreutils (sha256sum output)
5676bbb620dfd6c54c49e86831ea2577aa8d9cbc7e6ad5ea1f6848e9bc4f69fa  filename.txt

# BSD (shasum -a 256 / openssl dgst)
SHA256 (filename.txt) = 5676bbb620dfd6c54c49e86831ea2577aa8d9cbc7e6ad5ea1f6848e9bc4f69fa
```

Validation is strict: the file must be a single line, under 1024 bytes, with exactly one hex string of the expected length. If anything is ambiguous, no header is emitted.

## Build and Install

```bash
make
sudo make install
```

Or manually with `apxs`:

```bash
apxs -c mod_digest_fields.c
sudo apxs -i -a mod_digest_fields.so
```

Then load the module:

```apache
LoadModule digest_fields_module modules/mod_digest_fields.so
```

## Configuration Reference

All directives work in server config, virtual host, `<Directory>`, and `.htaccess` (with `FileInfo` override).

### DigestFields On|Off

Enable or disable the module. Default: `Off`.

```apache
<Directory "/var/www/downloads">
    DigestFields On
</Directory>
```

### DigestFieldsAlgorithm

Hash algorithm to use. Checked in order; first sidecar found wins. Default: `sha-256`.

```apache
# Prefer SHA-512, fall back to SHA-256
DigestFieldsAlgorithm sha-512 sha-256
```

| Algorithm | Sidecar Extension | Hex Length |
|-----------|-------------------|------------|
| sha-256   | `.sha256`         | 64 chars   |
| sha-512   | `.sha512`         | 128 chars  |

### DigestFieldsRepr On|Off

Also emit a `Repr-Digest` header for compressed files. The module strips the compression extension and looks for that file's sidecar. Default: `Off`.

```apache
DigestFields On
DigestFieldsRepr On
```

Supported compression extensions (default): `.gz`, `.bz2`, `.xz`, `.zst`, `.lz4`, `.lzma`, `.lzfse`, `.br`

### DigestFieldsCompression

Override the default compression extension list. Use bare names without dots.

```apache
# Only recognize .gz and .zst as compression extensions
DigestFieldsCompression gz zst
```

### DigestFieldsMatch

Only add headers for files matching a regex pattern (matched against the basename, not the full path).

```apache
# Only hash archives
DigestFieldsMatch "\.(tar\.gz|tar\.xz|tar\.zst|zip|iso)$"
```

### DigestFieldsDirectory

Store sidecar files in a subdirectory instead of alongside the content. Keeps directory listings clean.

```apache
# Sidecar for /files/data.json is /files/.checksum/data.json.sha256
DigestFieldsDirectory .checksum
```

## Client Algorithm Negotiation

Per RFC 9530, clients can request specific algorithms using the `Want-Content-Digest` and `Want-Repr-Digest` headers:

```bash
curl -H "Want-Content-Digest: sha-512=1, sha-256=0.5" http://localhost/files/data.json
```

The module respects client weights, filtered to algorithms configured on the server.

## Example Configurations

### Mirror server

Pre-compressed archives with integrity verification. Disabling on-the-fly compression prevents double-compression of already-compressed files.

```apache
<Directory "/var/www/mirror">
    DigestFields On
    DigestFieldsRepr On
    DigestFieldsMatch "\.(tar\.gz|tar\.xz|tar\.zst|zip)$"
    SetEnv no-gzip 1
    SetEnv no-brotli 1
</Directory>
```

### Static site with mod_deflate

For a static site where mod_deflate compresses `.js`, `.css`, and `.html` on the fly, no extra configuration is needed. The module automatically emits `Repr-Digest` for compressed responses and `Content-Digest` for uncompressed ones.

```apache
<Directory "/usr/local/www/my-app">
    DigestFields On
</Directory>
```

### Clean directory listings

Hide sidecar files in a subdirectory so they don't clutter `mod_autoindex` output.

```apache
<Directory "/var/www/releases">
    DigestFields On
    DigestFieldsDirectory .checksum
</Directory>
```

Sidecar layout:

```
releases/
    myapp-2.1.tar.gz
    myapp-2.0.tar.gz
    .checksum/
        myapp-2.1.tar.gz.sha256
        myapp-2.0.tar.gz.sha256
```

### SHA-512 with SHA-256 fallback

```apache
<Directory "/var/www/secure">
    DigestFields On
    DigestFieldsAlgorithm sha-512 sha-256
</Directory>
```

The module checks for `.sha512` first. If not found, it tries `.sha256`.

## Generating Sidecar Files

```bash
# Single file
sha256sum myapp-2.1.tar.gz > myapp-2.1.tar.gz.sha256

# All files in a directory
for f in /var/www/mirror/*.tar.gz; do
    sha256sum "$f" > "$f.sha256"
done

# Into a subdirectory
mkdir -p /var/www/mirror/.checksum
for f in /var/www/mirror/*.tar.gz; do
    sha256sum "$f" > "/var/www/mirror/.checksum/$(basename "$f").sha256"
done

# Both compressed and uncompressed (for Repr-Digest)
sha256sum archive.tar    > archive.tar.sha256
sha256sum archive.tar.gz > archive.tar.gz.sha256
```

On FreeBSD, use `shasum -a 256` or `sha256` instead of `sha256sum`. On macOS, use `shasum -a 256`. All output formats are supported.

## Important Notes

### mod_deflate / mod_brotli

The module is fully compatible with on-the-fly compression. When mod_deflate or mod_brotli compresses a response, the module automatically emits the sidecar hash as `Repr-Digest` instead of `Content-Digest`. This is the correct RFC 9530 behavior -- the sidecar hash represents the selected representation before content-encoding, not the compressed bytes on the wire.

```
No compression  →  Content-Digest: sha-256=:hash:    (hash of file = bytes on wire)
With gzip/br    →  Repr-Digest: sha-256=:hash:       (hash of file = representation)
```

For mirror servers serving pre-compressed archives (`.tar.gz`, `.tar.xz`), you may still want to disable on-the-fly compression to prevent double-compression:

```apache
SetEnv no-gzip 1
SetEnv no-brotli 1
```

### Symlinks

The module follows symlinks, consistent with Apache's `FollowSymLinks` directive. No special handling is performed.

### Missing sidecars

If a sidecar file doesn't exist, no header is added. This is silent and intentional -- the absence of a `Content-Digest` header simply means "not verified." Clients can decide whether to proceed.

## References

- [RFC 9530 -- Digest Fields](https://datatracker.ietf.org/doc/html/rfc9530)
- [RFC 8941 -- Structured Field Values for HTTP](https://datatracker.ietf.org/doc/html/rfc8941)

## License

Apache License, Version 2.0. See [LICENSE](LICENSE).
