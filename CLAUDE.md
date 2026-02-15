# mod_digest_fields

Apache module implementing RFC 9530 (Digest Fields). Adds `Content-Digest` and `Repr-Digest` headers for static files when corresponding sidecar checksum files exist.

## Purpose

When serving `foo.txt`, if `foo.txt.sha256` exists, respond with:

```
Content-Digest: sha-256=:VnYLtiDf1sVMSehoMeoYSw0u0cHNKh7A+4XSmaGSpEc=:
```

This allows clients to verify file integrity without a separate request.

## RFC 9530 Compliance

Compliant with [RFC 9530 (Digest Fields)](https://datatracker.ietf.org/doc/html/rfc9530):
- Header: `Content-Digest`
- Format: `sha-256=:base64hash:` (Structured Field byte sequence per RFC 8941)
- Optional: `Repr-Digest` header for uncompressed content representation
- Supports `Want-Content-Digest` and `Want-Repr-Digest` client preference headers

## Sidecar Files

Each file's checksum lives in a sidecar with the same name plus `.sha256` (or `.sha512`):

```
gtlds.json           ->  gtlds.json.sha256
gtlds.json.bz2       ->  gtlds.json.bz2.sha256
gtlds.json.zst       ->  gtlds.json.zst.sha256
```

Or, with `DigestFieldsDirectory .checksum`, in a subdirectory:

```
gtlds.json           ->  .checksum/gtlds.json.sha256
gtlds.json.zst       ->  .checksum/gtlds.json.zst.sha256
```

For Repr-Digest (uncompressed content), the module automatically strips the compression extension and looks for that file's checksum:

| Requested File | Content-Digest from | Repr-Digest from |
|----------------|---------------------|------------------|
| `gtlds.json.zst` | `gtlds.json.zst.sha256` | `gtlds.json.sha256` |
| `archive.tar.gz` | `archive.tar.gz.sha256` | `archive.tar.sha256` |

Supported compression extensions (default): `.gz`, `.bz2`, `.xz`, `.zst`, `.lz4`, `.lzma`, `.lzfse`, `.br`

Override the default list with `DigestFieldsCompression`.

## Supported Algorithms

| Algorithm | Extension | Hex Length | Status |
|-----------|-----------|------------|--------|
| SHA-256   | `.sha256` | 64 chars   | Required |
| SHA-512   | `.sha512` | 128 chars  | Required |

No MD5, SHA-1, or other deprecated algorithms. SHA-2 family only.

## Checksum File Parsing

The module extracts the hash by scanning for a valid hex string matching the expected length. Supports common formats:

```
# Format 1: Plain hash only
5676bbb620dfd6c54c49e86831ea2577aa8d9cbc7e6ad5ea1f6848e9bc4f69fa

# Format 2: GNU coreutils (sha256sum)
5676bbb620dfd6c54c49e86831ea2577aa8d9cbc7e6ad5ea1f6848e9bc4f69fa  filename.txt

# Format 3: BSD style (shasum -a 256, openssl dgst)
SHA256 (filename.txt) = 5676bbb620dfd6c54c49e86831ea2577aa8d9cbc7e6ad5ea1f6848e9bc4f69fa
```

**Validation rules (strict):**
1. File must contain exactly one line (trailing newline OK, multiple lines = malformed)
2. Sidecar file must be under 1024 bytes (truncated files are rejected)
3. Line must contain exactly one hex string of the expected length
4. Hex string: contiguous `[0-9a-fA-F]` of exact length (64 for SHA-256, 128 for SHA-512)
5. If zero or multiple valid hex strings found: malformed, skip
6. Hex is converted to base64 per RFC 8941 Structured Fields

**If there's any ambiguity, emit no header.** A malformed sidecar file is silently skipped. Clients expecting a digest header can treat its absence as "unverified" and decide whether to proceed.

## Configuration Directives

```apache
# Enable/disable (default: Off)
DigestFields On|Off

# Enable Repr-Digest header for uncompressed content (default: Off)
# Strips compression extension and looks for that file's .sha256
DigestFieldsRepr On|Off

# Algorithms to check, in order of preference (default: sha-256)
# Module checks for sidecar files in this order, uses first found
DigestFieldsAlgorithm sha-256
DigestFieldsAlgorithm sha-512

# Only add header for specific file types (optional, matches basename only)
DigestFieldsMatch "\.tar\.gz$|\.zip$|\.iso$"

# Store sidecar files in a subdirectory (optional)
# Default: sidecar files alongside content (foo.tar.gz.sha256)
# With this: sidecars in subdirectory (.checksum/foo.tar.gz.sha256)
DigestFieldsDirectory .checksum

# Override default compression extensions for Repr-Digest (optional)
# Use bare names without dots; default list is gz bz2 xz zst lz4 lzma lzfse br
DigestFieldsCompression gz bz2 zst lzfse
```

## Configuration Contexts

- Server config
- Virtual host
- Directory
- .htaccess (with FileInfo override)

## Example Configurations

### Basic: RFC 9530 compliant
```apache
<Directory "/var/www/downloads">
    DigestFields On
</Directory>
```
Output (no compression): `Content-Digest: sha-256=:base64hash:`
Output (with mod_deflate): `Repr-Digest: sha-256=:base64hash:`

### Compressed files with Repr-Digest
```apache
<Directory "/var/www/releases">
    DigestFields On
    DigestFieldsRepr On
    DigestFieldsMatch "\.(tar\.gz|tar\.xz|zip)$"
</Directory>
```
Output:
```
Content-Digest: sha-256=:compressedBase64:
Repr-Digest: sha-256=:uncompressedBase64:
```

### SHA-512 preference
```apache
<Directory "/var/www/secure">
    DigestFields On
    DigestFieldsAlgorithm sha-512
    DigestFieldsAlgorithm sha-256
</Directory>
```

### Mirror server (pre-compressed archives)
```apache
# For mirror servers serving pre-compressed archives with integrity verification.
# no-gzip/no-brotli prevents double-compression of already-compressed files.
<Directory "/var/www/mirror">
    DigestFields On
    DigestFieldsRepr On
    SetEnv no-gzip 1
    SetEnv no-brotli 1
</Directory>
```

### Static site with mod_deflate
```apache
# mod_deflate compresses .js/.css on the fly. The module automatically
# emits Repr-Digest (not Content-Digest) for compressed responses.
<Directory "/usr/local/www/my-app">
    DigestFields On
</Directory>
```

### Hidden sidecar directory (clean listings)
```apache
# Store checksums in a hidden subdirectory to avoid cluttering directory listings.
# File: /var/www/mirror/foo.tar.gz
# Sidecar: /var/www/mirror/.checksum/foo.tar.gz.sha256
<Directory "/var/www/mirror">
    DigestFields On
    DigestFieldsDirectory .checksum
</Directory>
```

## Want-Content-Digest / Want-Repr-Digest

Per RFC 9530, clients can request specific algorithms using the `Want-Content-Digest` and `Want-Repr-Digest` headers:

```
Want-Content-Digest: sha-512=1, sha-256=0.5
```

The module will:
1. Parse the header and extract algorithm preferences with weights (0.0-1.0)
2. Filter to only algorithms that are configured on the server
3. Sort by weight (highest first)
4. Use this order instead of the server-configured order

If a client requests `sha-512=1, sha-256=0.5`, the server will prefer SHA-512 if a `.sha512` sidecar exists, falling back to SHA-256 otherwise.

**Note:** Algorithms not configured via `DigestFieldsAlgorithm` are ignored in the Want header.

## Implementation Notes

### Module Hooks (Two-Phase Architecture)

The module uses a two-phase approach to correctly handle on-the-fly compression:

**Phase 1: Fixup handler** (`ap_hook_fixups`, `APR_HOOK_MIDDLE`)
- Runs after URI translation, before content generation
- Only handles main requests, not subrequests
- Checks if request is for a regular file (stat)
- Looks up sidecar file(s) and parses checksum (hex → binary → base64)
- Stashes computed digest values in `r->notes` (not `r->headers_out`)
- Adds the output filter to the chain only if a digest was found

**Phase 2: Output filter** (`AP_FTYPE_PROTOCOL`)
- Runs after mod_deflate (`AP_FTYPE_CONTENT_SET`) has set `Content-Encoding`
- Checks `r->headers_out` for `Content-Encoding` to determine header name:
  - **No encoding**: sidecar hash → `Content-Digest` (bytes on wire = file on disk)
  - **Encoding present**: sidecar hash → `Repr-Digest` (hash of representation before encoding)
- Emits `Repr-Digest` from DigestFieldsRepr sidecar if set (pre-compressed archives)
- Removes itself from the filter chain after first invocation

### Performance Considerations
- One stat per algorithm tried for sidecar lookup (stops at first found)
- Checksum file read only when sidecar exists
- Single-line-only parsing keeps reads minimal
- No caching of parsed checksums; each request re-reads the sidecar file
- Output filter is only added to the chain when a sidecar was found

### mod_deflate / mod_brotli Compatibility

The module is fully compatible with on-the-fly compression (mod_deflate, mod_brotli). When compression is applied, the module automatically emits the sidecar hash as `Repr-Digest` instead of `Content-Digest`, which is the correct RFC 9530 semantic -- the sidecar hash represents the selected representation before content-encoding.

| Scenario | Content-Encoding | Header Emitted | Hash Of |
|----------|-----------------|----------------|---------|
| No compression | *(none)* | `Content-Digest` | File on disk (= bytes on wire) |
| mod_deflate/brotli | gzip/br | `Repr-Digest` | File on disk (= representation before encoding) |
| Pre-compressed archive | *(none)* | `Content-Digest` | Compressed file on disk (= bytes on wire) |

For mirror servers serving pre-compressed archives, you may still want to disable on-the-fly compression as a precaution (to prevent double-compression of already-compressed files):
```apache
SetEnv no-gzip 1
SetEnv no-brotli 1
```

### Symlink Behavior

The module follows symlinks when checking for both the target file and sidecar files. It uses the final resolved path after Apache's URI translation. No special handling for symlinks is performed.

### DigestFieldsMatch Pattern Notes

- Pattern matches against the **basename only** (filename without directory path)
- Uses POSIX Extended Regular Expressions (ERE)
- Keep patterns simple to avoid ReDoS concerns with pathological input
- First algorithm match wins (order of `DigestFieldsAlgorithm` directives matters)

### Error Handling
- Missing sidecar file: No header (silent, normal case)
- Malformed checksum file: No header (silent - not our problem to fix)
- File too large (>= 1024 bytes): No header
- Multiple lines: Malformed, no header
- Zero valid hex strings: Malformed, no header
- Multiple valid hex strings: Ambiguous, no header
- Unreadable sidecar file: No header, optional debug log

**Philosophy**: If we can't be 100% confident in the checksum, don't serve one. Clients can treat missing header as "unverified".

### Security
- Sidecar file must be in same directory as target file (or in the configured `DigestFieldsDirectory` subdirectory)
- No path traversal in sidecar filename construction
- `DigestFieldsDirectory` rejects `/`, `\`, `..`, and `.`
- Validate hex string strictly (no partial matches)

## Build

```sh
make
# or
apxs -c mod_digest_fields.c
```

## Install

```sh
sudo make install
# or
sudo apxs -i -a mod_digest_fields.so
```

## Apache Configuration

```apache
LoadModule digest_fields_module modules/mod_digest_fields.so
```

## Testing

```sh
# Create test file and checksum
echo "test content" > /tmp/test.txt
sha256sum /tmp/test.txt > /tmp/test.txt.sha256

# Expected response header:
# Content-Digest: sha-256=:base64hash:

# For compressed files with representation digest:
# Both the compressed and uncompressed files have their own .sha256
sha256sum archive.tar > archive.tar.sha256
gzip -k archive.tar
sha256sum archive.tar.gz > archive.tar.gz.sha256

# When requesting archive.tar.gz with DigestFieldsRepr On:
# Content-Digest: sha-256=:compressedHash:   (from archive.tar.gz.sha256)
# Repr-Digest: sha-256=:uncompressedHash:    (from archive.tar.sha256)

# Test Want-Content-Digest client preference:
curl -I -H "Want-Content-Digest: sha-512=1, sha-256=0.5" http://localhost/file.txt
# Server will prefer sha-512 if .sha512 sidecar exists

# Verify with the included script:
python3 verify.py http://localhost/file.txt
```

## References

- [RFC 9530 - Digest Fields](https://datatracker.ietf.org/doc/html/rfc9530)
- [RFC 8941 - Structured Field Values](https://datatracker.ietf.org/doc/html/rfc8941)
