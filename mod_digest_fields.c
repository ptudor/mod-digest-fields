/*
 * mod_digest_fields - Apache module for RFC 9530 Digest Fields
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * RFC 9530 (Digest Fields) compliant:
 *   Content-Digest: sha-256=:base64hash:
 *   Repr-Digest: sha-256=:base64hash:  (optional, for uncompressed content)
 *
 * Sidecar files:
 *   file.txt.sha256      -> Content-Digest (hash of file.txt)
 *   file.txt.gz.sha256   -> Content-Digest (hash of file.txt.gz)
 *   For Repr-Digest, compression extension is stripped to find base file's sidecar
 */

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"
#include "http_request.h"
#include "apr_strings.h"
#include "apr_file_io.h"
#include "apr_base64.h"
#include "ap_regex.h"
#include "apr_lib.h"

#define CHECKSUM_MAX_FILE_SIZE 1024
#define CHECKSUM_ENABLED_UNSET -1

/* Algorithm definitions */
typedef struct {
    const char *name;       /* Algorithm name: "sha-256" */
    const char *extension;  /* File extension: ".sha256" */
    int hex_length;         /* Expected hex length: 64 for SHA-256 */
    int binary_length;      /* Binary hash length: 32 for SHA-256 */
} content_digest_algo;

static const content_digest_algo known_algorithms[] = {
    { "sha-256", ".sha256", 64, 32 },
    { "sha-512", ".sha512", 128, 64 },
    { NULL, NULL, 0, 0 }
};

/* Known compression extensions to strip for Repr-Digest */
static const char *compression_extensions[] = {
    ".gz", ".bz2", ".xz", ".zst", ".lz4", ".lzma", ".lzfse", ".br",
    NULL
};

/* Per-directory configuration */
typedef struct {
    int enabled;                      /* -1 unset, 0 off, 1 on */
    int repr_digest_enabled;          /* -1 unset, 0 off, 1 on */
    apr_array_header_t *algorithms;   /* Array of content_digest_algo pointers */
    ap_regex_t *match_regex;          /* Optional filename filter */
    const char *sidecar_dir;          /* Subdirectory for sidecar files (e.g., ".checksum") */
    apr_array_header_t *compression_exts;  /* Configured compression extensions (e.g., ".gz") */
} content_digest_dir_config;

module AP_MODULE_DECLARE_DATA digest_fields_module;

/* Find algorithm by name */
static const content_digest_algo *find_algorithm(const char *name)
{
    int i;
    for (i = 0; known_algorithms[i].name != NULL; i++) {
        if (strcasecmp(known_algorithms[i].name, name) == 0) {
            return &known_algorithms[i];
        }
    }
    return NULL;
}

/* Create per-directory configuration */
static void *content_digest_create_dir_config(apr_pool_t *p, char *dir)
{
    content_digest_dir_config *conf = apr_pcalloc(p, sizeof(content_digest_dir_config));
    conf->enabled = CHECKSUM_ENABLED_UNSET;
    conf->repr_digest_enabled = CHECKSUM_ENABLED_UNSET;
    conf->algorithms = NULL;
    conf->match_regex = NULL;
    conf->sidecar_dir = NULL;
    conf->compression_exts = NULL;
    return conf;
}

/* Merge per-directory configurations */
static void *content_digest_merge_dir_config(apr_pool_t *p, void *basev, void *overridesv)
{
    content_digest_dir_config *base = (content_digest_dir_config *)basev;
    content_digest_dir_config *overrides = (content_digest_dir_config *)overridesv;
    content_digest_dir_config *conf = apr_pcalloc(p, sizeof(content_digest_dir_config));

    conf->enabled = (overrides->enabled != CHECKSUM_ENABLED_UNSET)
                    ? overrides->enabled : base->enabled;
    conf->repr_digest_enabled = (overrides->repr_digest_enabled != CHECKSUM_ENABLED_UNSET)
                                ? overrides->repr_digest_enabled : base->repr_digest_enabled;
    conf->algorithms = overrides->algorithms
                       ? overrides->algorithms : base->algorithms;
    conf->match_regex = overrides->match_regex
                        ? overrides->match_regex : base->match_regex;
    conf->sidecar_dir = overrides->sidecar_dir
                        ? overrides->sidecar_dir : base->sidecar_dir;
    conf->compression_exts = overrides->compression_exts
                             ? overrides->compression_exts : base->compression_exts;

    return conf;
}

/* Directive handler: DigestFields On|Off */
static const char *set_content_digest(cmd_parms *cmd, void *cfg, int flag)
{
    content_digest_dir_config *conf = (content_digest_dir_config *)cfg;
    conf->enabled = flag ? 1 : 0;
    return NULL;
}

/* Directive handler: DigestFieldsRepr On|Off */
static const char *set_content_digest_repr(cmd_parms *cmd, void *cfg, int flag)
{
    content_digest_dir_config *conf = (content_digest_dir_config *)cfg;
    conf->repr_digest_enabled = flag ? 1 : 0;
    return NULL;
}

/* Directive handler: DigestFieldsAlgorithm <algo> */
static const char *set_content_digest_algorithm(cmd_parms *cmd, void *cfg,
                                          const char *algo)
{
    content_digest_dir_config *conf = (content_digest_dir_config *)cfg;
    const content_digest_algo *a = find_algorithm(algo);

    if (a == NULL) {
        return apr_psprintf(cmd->pool,
            "DigestFieldsAlgorithm: unknown algorithm '%s'. "
            "Supported: sha-256, sha-512", algo);
    }

    if (conf->algorithms == NULL) {
        conf->algorithms = apr_array_make(cmd->pool, 2, sizeof(const content_digest_algo *));
    }

    *(const content_digest_algo **)apr_array_push(conf->algorithms) = a;
    return NULL;
}

/* Directive handler: DigestFieldsMatch <regex> */
static const char *set_content_digest_match(cmd_parms *cmd, void *cfg,
                                      const char *pattern)
{
    content_digest_dir_config *conf = (content_digest_dir_config *)cfg;
    ap_regex_t *regex;

    regex = ap_pregcomp(cmd->pool, pattern, AP_REG_EXTENDED | AP_REG_NOSUB);
    if (regex == NULL) {
        return apr_psprintf(cmd->pool,
            "DigestFieldsMatch: invalid regex pattern '%s'", pattern);
    }

    conf->match_regex = regex;
    return NULL;
}

/* Directive handler: DigestFieldsDirectory <subdir> */
static const char *set_content_digest_directory(cmd_parms *cmd, void *cfg,
                                                const char *subdir)
{
    content_digest_dir_config *conf = (content_digest_dir_config *)cfg;

    /* Security: reject path traversal attempts */
    if (strchr(subdir, '/') != NULL || strchr(subdir, '\\') != NULL) {
        return "DigestFieldsDirectory: subdirectory name cannot contain path separators";
    }
    if (strcmp(subdir, "..") == 0 || strcmp(subdir, ".") == 0) {
        return "DigestFieldsDirectory: invalid subdirectory name";
    }

    conf->sidecar_dir = apr_pstrdup(cmd->pool, subdir);
    return NULL;
}

/* Directive handler: DigestFieldsCompression <ext> [<ext> ...] */
static const char *set_content_digest_compression(cmd_parms *cmd, void *cfg,
                                                   const char *ext)
{
    content_digest_dir_config *conf = (content_digest_dir_config *)cfg;
    const char *dotted;

    /* Validate: must be alphanumeric, no dots or slashes */
    const char *p;
    for (p = ext; *p != '\0'; p++) {
        if (!apr_isalnum(*p)) {
            return apr_psprintf(cmd->pool,
                "DigestFieldsCompression: invalid extension '%s' "
                "(use bare name like 'gz', not '.gz')", ext);
        }
    }

    if (conf->compression_exts == NULL) {
        conf->compression_exts = apr_array_make(cmd->pool, 4, sizeof(const char *));
    }

    /* Store with leading dot for matching */
    dotted = apr_pstrcat(cmd->pool, ".", ext, NULL);
    *(const char **)apr_array_push(conf->compression_exts) = dotted;
    return NULL;
}

/* Check if a character is a valid hex digit */
static int is_hex_char(char c)
{
    return (c >= '0' && c <= '9') ||
           (c >= 'a' && c <= 'f') ||
           (c >= 'A' && c <= 'F');
}

/* Convert hex character to nibble value */
static unsigned char hex_to_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return 0;
}

/* Convert hex string to binary. Returns allocated binary buffer. */
static unsigned char *hex_to_binary(apr_pool_t *p, const char *hex, int hex_len)
{
    unsigned char *binary;
    int i;
    int binary_len = hex_len / 2;

    binary = apr_palloc(p, binary_len);
    for (i = 0; i < binary_len; i++) {
        binary[i] = (hex_to_nibble(hex[i * 2]) << 4) | hex_to_nibble(hex[i * 2 + 1]);
    }
    return binary;
}

/* Convert binary to base64. Returns allocated base64 string. */
static char *binary_to_base64(apr_pool_t *p, const unsigned char *binary, int binary_len)
{
    int base64_len = apr_base64_encode_len(binary_len);
    char *base64 = apr_palloc(p, base64_len);
    apr_base64_encode(base64, (const char *)binary, binary_len);
    return base64;
}

/*
 * Strip compression extension from filename.
 * Returns base filename without compression extension, or NULL if no match.
 * Example: "gtlds.json.zst" -> "gtlds.json"
 *
 * Uses configured_exts if provided, otherwise falls back to the default
 * compression_extensions list.
 */
static const char *strip_compression_extension(apr_pool_t *p, const char *filename,
                                                apr_array_header_t *configured_exts)
{
    size_t filename_len = strlen(filename);
    int i;

    if (configured_exts != NULL && configured_exts->nelts > 0) {
        for (i = 0; i < configured_exts->nelts; i++) {
            const char *ext = ((const char **)configured_exts->elts)[i];
            size_t ext_len = strlen(ext);
            if (filename_len > ext_len &&
                strcasecmp(filename + filename_len - ext_len, ext) == 0) {
                return apr_pstrndup(p, filename, filename_len - ext_len);
            }
        }
    } else {
        for (i = 0; compression_extensions[i] != NULL; i++) {
            size_t ext_len = strlen(compression_extensions[i]);
            if (filename_len > ext_len &&
                strcasecmp(filename + filename_len - ext_len, compression_extensions[i]) == 0) {
                return apr_pstrndup(p, filename, filename_len - ext_len);
            }
        }
    }
    return NULL;
}

/*
 * Structure for Want-*-Digest preferences
 */
typedef struct {
    const content_digest_algo *algo;
    double weight;
} want_digest_pref;

/*
 * Compare function for sorting Want-*-Digest preferences by weight (descending)
 */
static int compare_want_prefs(const void *a, const void *b)
{
    const want_digest_pref *pa = (const want_digest_pref *)a;
    const want_digest_pref *pb = (const want_digest_pref *)b;
    if (pb->weight > pa->weight) return 1;
    if (pb->weight < pa->weight) return -1;
    return 0;
}

/*
 * Parse Want-Content-Digest or Want-Repr-Digest header.
 * Format per RFC 9530: sha-256=1, sha-512=0.5
 *
 * Returns array of content_digest_algo pointers sorted by preference,
 * or NULL if header is missing or malformed.
 * Only algorithms in configured_algos are included in the result.
 */
static apr_array_header_t *parse_want_digest_header(request_rec *r,
                                                     const char *header_value,
                                                     apr_array_header_t *configured_algos)
{
    apr_array_header_t *prefs;
    apr_array_header_t *result;
    char *value_copy, *token, *last;
    int i;

    if (header_value == NULL || *header_value == '\0') {
        return NULL;
    }

    prefs = apr_array_make(r->pool, 4, sizeof(want_digest_pref));
    value_copy = apr_pstrdup(r->pool, header_value);

    /* Parse comma-separated list: sha-256=1, sha-512=0.5 */
    for (token = apr_strtok(value_copy, ",", &last);
         token != NULL;
         token = apr_strtok(NULL, ",", &last)) {

        char *algo_name, *weight_str, *eq_pos;
        const content_digest_algo *algo;
        double weight = 1.0;
        int is_configured = 0;

        /* Skip leading whitespace */
        while (*token == ' ' || *token == '\t') token++;

        /* Find equals sign */
        eq_pos = strchr(token, '=');
        if (eq_pos == NULL) {
            /* No weight specified, default to 1.0 */
            algo_name = token;
            /* Trim trailing whitespace */
            char *end = algo_name + strlen(algo_name) - 1;
            while (end > algo_name && (*end == ' ' || *end == '\t')) {
                *end-- = '\0';
            }
        } else {
            *eq_pos = '\0';
            algo_name = token;
            weight_str = eq_pos + 1;

            /* Trim trailing whitespace from algo name */
            char *end = algo_name + strlen(algo_name) - 1;
            while (end > algo_name && (*end == ' ' || *end == '\t')) {
                *end-- = '\0';
            }

            /* Skip leading whitespace on weight */
            while (*weight_str == ' ' || *weight_str == '\t') weight_str++;

            /* Parse weight (0.0 to 1.0) */
            weight = strtod(weight_str, NULL);
            if (weight < 0.0) weight = 0.0;
            if (weight > 1.0) weight = 1.0;
        }

        /* Look up algorithm */
        algo = find_algorithm(algo_name);
        if (algo == NULL) {
            continue;  /* Unknown algorithm, skip */
        }

        /* Check if this algorithm is in our configured list */
        for (i = 0; i < configured_algos->nelts; i++) {
            const content_digest_algo *conf_algo =
                ((const content_digest_algo **)configured_algos->elts)[i];
            if (conf_algo == algo) {
                is_configured = 1;
                break;
            }
        }

        if (!is_configured) {
            continue;  /* Not configured, skip */
        }

        /* Skip if weight is 0 (client doesn't want this algorithm) */
        if (weight == 0.0) {
            continue;
        }

        /* Add to preferences */
        want_digest_pref *pref = (want_digest_pref *)apr_array_push(prefs);
        pref->algo = algo;
        pref->weight = weight;
    }

    if (prefs->nelts == 0) {
        return NULL;
    }

    /* Sort by weight descending */
    qsort(prefs->elts, prefs->nelts, sizeof(want_digest_pref), compare_want_prefs);

    /* Convert to array of algo pointers */
    result = apr_array_make(r->pool, prefs->nelts, sizeof(const content_digest_algo *));
    for (i = 0; i < prefs->nelts; i++) {
        want_digest_pref *pref = &((want_digest_pref *)prefs->elts)[i];
        *(const content_digest_algo **)apr_array_push(result) = pref->algo;
    }

    return result;
}

/*
 * Parse checksum file and extract hex hash.
 * Returns lowercase hex string on success, NULL on failure.
 *
 * Validation rules:
 * - File must contain exactly one line (trailing newline OK)
 * - Line must contain exactly one hex string of expected length
 * - If zero or multiple valid hex strings: malformed, return NULL
 */
static const char *parse_checksum_file(request_rec *r, const char *sidecar_path,
                                       int expected_hex_len, const char **reason)
{
    apr_file_t *f;
    apr_status_t rv;
    char buf[CHECKSUM_MAX_FILE_SIZE + 1];
    apr_size_t bytes_read;
    char *p, *hex_start = NULL;
    int in_hex = 0;
    int hex_len = 0;
    char *result;
    int i;

    *reason = NULL;

    rv = apr_file_open(&f, sidecar_path, APR_READ | APR_BUFFERED,
                       APR_OS_DEFAULT, r->pool);
    if (rv != APR_SUCCESS) {
        return NULL;  /* File doesn't exist or can't be read - normal case */
    }

    bytes_read = CHECKSUM_MAX_FILE_SIZE;
    rv = apr_file_read(f, buf, &bytes_read);
    apr_file_close(f);

    if (rv != APR_SUCCESS && rv != APR_EOF) {
        *reason = "read error";
        return NULL;
    }

    buf[bytes_read] = '\0';

    /* Check for file too large (truncated read) */
    if (bytes_read == CHECKSUM_MAX_FILE_SIZE) {
        *reason = "file too large";
        return NULL;
    }

    /* Check for multiple lines: newline not at end means multiple lines */
    for (p = buf; *p != '\0'; p++) {
        if (*p == '\n' && *(p + 1) != '\0') {
            *reason = "multiple lines";
            return NULL;
        }
        if (*p == '\r' && *(p + 1) != '\n') {
            *reason = "malformed line ending";
            return NULL;
        }
    }

    /* Scan for hex sequences of exact expected length.
     * Save the first valid match in found_hex_start; reject if we find a second. */
    char *found_hex_start = NULL;
    p = buf;
    while (*p != '\0') {
        if (is_hex_char(*p)) {
            if (!in_hex) {
                in_hex = 1;
                hex_start = p;
                hex_len = 1;
            } else {
                hex_len++;
            }
        } else {
            if (in_hex) {
                /* End of hex sequence - check if it's the right length */
                if (hex_len == expected_hex_len) {
                    if (found_hex_start != NULL) {
                        *reason = "multiple valid hex strings";
                        return NULL;
                    }
                    found_hex_start = hex_start;
                }
                in_hex = 0;
            }
        }
        p++;
    }

    /* Handle hex sequence at end of buffer */
    if (in_hex && hex_len == expected_hex_len) {
        if (found_hex_start != NULL) {
            *reason = "multiple valid hex strings";
            return NULL;
        }
        found_hex_start = hex_start;
    }

    if (found_hex_start == NULL) {
        *reason = "no valid hex string found";
        return NULL;
    }

    /* Use the saved position from the first scan */
    hex_start = found_hex_start;

    /* Copy and lowercase the hex string */
    result = apr_palloc(r->pool, expected_hex_len + 1);
    for (i = 0; i < expected_hex_len; i++) {
        char c = hex_start[i];
        if (c >= 'A' && c <= 'F') {
            result[i] = c + ('a' - 'A');
        } else {
            result[i] = c;
        }
    }
    result[expected_hex_len] = '\0';

    return result;
}

/*
 * Try to find and parse a sidecar checksum file.
 * Returns the hex hash on success, NULL on failure.
 *
 * If sidecar_dir is set, looks for: dirname/sidecar_dir/basename.sha256
 * Otherwise, looks for: filepath.sha256
 */
static const char *find_sidecar_checksum(request_rec *r,
                                         const char *base_path,
                                         const content_digest_algo *algo,
                                         const char *sidecar_dir,
                                         const char **reason)
{
    const char *sidecar_path;
    apr_finfo_t sidecar_finfo;

    if (sidecar_dir != NULL) {
        /* Construct path: dirname/sidecar_dir/basename.ext */
        const char *last_slash = strrchr(base_path, '/');
        if (last_slash != NULL) {
            const char *dirname = apr_pstrndup(r->pool, base_path, last_slash - base_path);
            const char *basename = last_slash + 1;
            sidecar_path = apr_pstrcat(r->pool, dirname, "/", sidecar_dir, "/",
                                       basename, algo->extension, NULL);
        } else {
            /* No directory component - just use sidecar_dir/basename */
            sidecar_path = apr_pstrcat(r->pool, sidecar_dir, "/",
                                       base_path, algo->extension, NULL);
        }
    } else {
        /* Default: sidecar alongside the file */
        sidecar_path = apr_pstrcat(r->pool, base_path, algo->extension, NULL);
    }

    if (apr_stat(&sidecar_finfo, sidecar_path, APR_FINFO_TYPE, r->pool) != APR_SUCCESS) {
        return NULL;
    }
    if (sidecar_finfo.filetype != APR_REG) {
        return NULL;
    }

    return parse_checksum_file(r, sidecar_path, algo->hex_length, reason);
}

/*
 * Format the header value per RFC 9530.
 * Output: sha-256=:base64:
 */
static char *format_header_value(request_rec *r, const content_digest_algo *algo,
                                 const char *hex_hash)
{
    /* RFC 9530: convert hex to binary, then to base64 */
    unsigned char *binary = hex_to_binary(r->pool, hex_hash, algo->hex_length);
    char *base64 = binary_to_base64(r->pool, binary, algo->binary_length);
    return apr_psprintf(r->pool, "%s=:%s:", algo->name, base64);
}

/* Main fixup handler */
static int content_digest_fixup_handler(request_rec *r)
{
    content_digest_dir_config *conf;
    apr_finfo_t finfo;
    apr_array_header_t *algorithms;
    const content_digest_algo *default_algo;
    int i;

    /* Only handle main requests, not subrequests */
    if (r->main != NULL) {
        return DECLINED;
    }

    /* Get directory configuration */
    conf = ap_get_module_config(r->per_dir_config, &digest_fields_module);
    if (conf == NULL || conf->enabled != 1) {
        return DECLINED;
    }

    /* Must have a filename */
    if (r->filename == NULL) {
        return DECLINED;
    }

    /* Check if it's a regular file */
    if (apr_stat(&finfo, r->filename, APR_FINFO_TYPE, r->pool) != APR_SUCCESS) {
        return DECLINED;
    }
    if (finfo.filetype != APR_REG) {
        return DECLINED;
    }

    /* Check filename match regex if configured */
    if (conf->match_regex != NULL) {
        const char *basename = strrchr(r->filename, '/');
        basename = basename ? basename + 1 : r->filename;
        if (ap_regexec(conf->match_regex, basename, 0, NULL, 0) != 0) {
            return DECLINED;
        }
    }

    /* Determine algorithms to try */
    algorithms = conf->algorithms;
    if (algorithms == NULL || algorithms->nelts == 0) {
        /* Default to SHA-256 */
        default_algo = find_algorithm("sha-256");
        if (default_algo == NULL) {
            ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
                "mod_digest_fields: sha-256 algorithm not found in known_algorithms");
            return DECLINED;
        }
        algorithms = apr_array_make(r->pool, 1, sizeof(const content_digest_algo *));
        *(const content_digest_algo **)apr_array_push(algorithms) = default_algo;
    }

    /* Check for Want-Content-Digest header (RFC 9530) */
    {
        const char *want_header = apr_table_get(r->headers_in, "Want-Content-Digest");
        if (want_header != NULL) {
            apr_array_header_t *client_prefs =
                parse_want_digest_header(r, want_header, algorithms);
            if (client_prefs != NULL && client_prefs->nelts > 0) {
                algorithms = client_prefs;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "mod_digest_fields: using client algorithm preferences from Want-Content-Digest");
            }
        }
    }

    /* Try each algorithm in order for Content-Digest */
    for (i = 0; i < algorithms->nelts; i++) {
        const content_digest_algo *algo = ((const content_digest_algo **)algorithms->elts)[i];
        const char *hex_hash;
        const char *reason;
        char *header_value;

        hex_hash = find_sidecar_checksum(r, r->filename, algo, conf->sidecar_dir, &reason);
        if (hex_hash == NULL) {
            if (reason != NULL) {
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "mod_digest_fields: skipping malformed sidecar for %s: %s",
                    r->filename, reason);
            }
            continue;
        }

        /* Success - add Content-Digest header */
        header_value = format_header_value(r, algo, hex_hash);
        apr_table_set(r->headers_out, "Content-Digest", header_value);

        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
            "mod_digest_fields: added Content-Digest: %s for %s",
            header_value, r->filename);

        break;  /* Use first found algorithm */
    }

    /* Also check for Repr-Digest if enabled */
    if (conf->repr_digest_enabled == 1) {
        const char *base_filename;
        apr_array_header_t *repr_algorithms = algorithms;

        /* Check for Want-Repr-Digest header */
        const char *want_repr_header = apr_table_get(r->headers_in, "Want-Repr-Digest");
        if (want_repr_header != NULL) {
            apr_array_header_t *repr_prefs =
                parse_want_digest_header(r, want_repr_header, algorithms);
            if (repr_prefs != NULL && repr_prefs->nelts > 0) {
                repr_algorithms = repr_prefs;
                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "mod_digest_fields: using client algorithm preferences from Want-Repr-Digest");
            }
        }

        /* Strip compression extension to find the base file */
        base_filename = strip_compression_extension(r->pool, r->filename,
                                                     conf->compression_exts);
        if (base_filename != NULL) {
            for (i = 0; i < repr_algorithms->nelts; i++) {
                const content_digest_algo *algo = ((const content_digest_algo **)repr_algorithms->elts)[i];
                const char *hex_hash;
                const char *reason;
                char *header_value;

                /* Repr-Digest sidecar: gtlds.json.sha256 (for gtlds.json.zst) */
                hex_hash = find_sidecar_checksum(r, base_filename, algo, conf->sidecar_dir, &reason);
                if (hex_hash == NULL) {
                    if (reason != NULL) {
                        ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                            "mod_digest_fields: skipping malformed repr sidecar for %s: %s",
                            base_filename, reason);
                    }
                    continue;
                }

                /* Success - add Repr-Digest header */
                header_value = format_header_value(r, algo, hex_hash);
                apr_table_set(r->headers_out, "Repr-Digest", header_value);

                ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r,
                    "mod_digest_fields: added Repr-Digest: %s for %s (repr of %s)",
                    header_value, r->filename, base_filename);

                break;  /* Use first found algorithm */
            }
        }
    }

    return DECLINED;
}

/* Register hooks */
static void content_digest_register_hooks(apr_pool_t *p)
{
    ap_hook_fixups(content_digest_fixup_handler, NULL, NULL, APR_HOOK_MIDDLE);
}

/* Configuration directives */
static const command_rec content_digest_directives[] = {
    AP_INIT_FLAG("DigestFields", set_content_digest, NULL,
                 RSRC_CONF | OR_FILEINFO, "Enable RFC 9530 digest headers (On/Off)"),
    AP_INIT_FLAG("DigestFieldsRepr", set_content_digest_repr, NULL,
                 RSRC_CONF | OR_FILEINFO, "Also emit Repr-Digest header for compressed files (On/Off)"),
    AP_INIT_ITERATE("DigestFieldsAlgorithm", set_content_digest_algorithm, NULL,
                    RSRC_CONF | OR_FILEINFO, "Hash algorithm(s) to use (sha-256, sha-512)"),
    AP_INIT_TAKE1("DigestFieldsMatch", set_content_digest_match, NULL,
                  RSRC_CONF | OR_FILEINFO, "Regex pattern to match filenames"),
    AP_INIT_TAKE1("DigestFieldsDirectory", set_content_digest_directory, NULL,
                  RSRC_CONF | OR_FILEINFO, "Subdirectory for sidecar files (e.g., '.checksum')"),
    AP_INIT_ITERATE("DigestFieldsCompression", set_content_digest_compression, NULL,
                    RSRC_CONF | OR_FILEINFO,
                    "Compression extensions for Repr-Digest (e.g., 'gz bz2 zst lzfse')"),
    { NULL }
};

/* Module declaration */
AP_DECLARE_MODULE(digest_fields) = {
    STANDARD20_MODULE_STUFF,
    content_digest_create_dir_config,     /* create per-dir config */
    content_digest_merge_dir_config,      /* merge per-dir config */
    NULL,                           /* create per-server config */
    NULL,                           /* merge per-server config */
    content_digest_directives,            /* configuration directives */
    content_digest_register_hooks         /* register hooks */
};
