/*
 * upcouch.c
 *
 * Upload files as attachments to CouchDB.
 * - Base64-encodes file contents
 * - Wraps them in a JSON document with _attachments
 * - Optionally uses deterministic document IDs (-n)
 * - Recursive parallel upload mode (-p N -r <folder>)
 *
 * Build:
 *   cc -Wall -Wextra -O2 -o upcouch upcouch.c -lcurl -lpthread
 *
 */

#define _POSIX_C_SOURCE 200809L

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>
#include <ctype.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <pthread.h>
#include <unistd.h>

#define MAX_FILE_SIZE 4294967296ULL   /* 4 GiB */
#define MAX_THREADS   64

/* Deterministic ID mode */
static int USE_DETERMINISTIC_ID = 0;

/* ------------------------------
 * Minimal SHA-256 implementation
 * Public-domain style, compact
 * ------------------------------ */

typedef struct {
    uint64_t bitlen;
    uint32_t state[8];
    uint8_t data[64];
    uint32_t datalen;
} sha256_ctx;

static const uint32_t k256[64] = {
    0x428a2f98UL,0x71374491UL,0xb5c0fbcfUL,0xe9b5dba5UL,0x3956c25bUL,0x59f111f1UL,0x923f82a4UL,0xab1c5ed5UL,
    0xd807aa98UL,0x12835b01UL,0x243185beUL,0x550c7dc3UL,0x72be5d74UL,0x80deb1feUL,0x9bdc06a7UL,0xc19bf174UL,
    0xe49b69c1UL,0xefbe4786UL,0x0fc19dc6UL,0x240ca1ccUL,0x2de92c6fUL,0x4a7484aaUL,0x5cb0a9dcUL,0x76f988daUL,
    0x983e5152UL,0xa831c66dUL,0xb00327c8UL,0xbf597fc7UL,0xc6e00bf3UL,0xd5a79147UL,0x06ca6351UL,0x14292967UL,
    0x27b70a85UL,0x2e1b2138UL,0x4d2c6dfcUL,0x53380d13UL,0x650a7354UL,0x766a0abbUL,0x81c2c92eUL,0x92722c85UL,
    0xa2bfe8a1UL,0xa81a664bUL,0xc24b8b70UL,0xc76c51a3UL,0xd192e819UL,0xd6990624UL,0xf40e3585UL,0x106aa070UL,
    0x19a4c116UL,0x1e376c08UL,0x2748774cUL,0x34b0bcb5UL,0x391c0cb3UL,0x4ed8aa4aUL,0x5b9cca4fUL,0x682e6ff3UL,
    0x748f82eeUL,0x78a5636fUL,0x84c87814UL,0x8cc70208UL,0x90befffaUL,0xa4506cebUL,0xbef9a3f7UL,0xc67178f2UL
};

static inline uint32_t rotr32(uint32_t x, uint32_t n) {
    return (x >> n) | (x << (32 - n));
}

static void sha256_transform(sha256_ctx *ctx, const uint8_t data[64]) {
    uint32_t m[64];
    uint32_t a,b,c,d,e,f,g,h;
    unsigned i;

    for (i = 0; i < 16; ++i) {
        m[i] = ((uint32_t)data[i*4] << 24) |
               ((uint32_t)data[i*4 + 1] << 16) |
               ((uint32_t)data[i*4 + 2] << 8) |
               ((uint32_t)data[i*4 + 3]);
    }
    for (i = 16; i < 64; ++i) {
        uint32_t s0 = rotr32(m[i-15],7) ^ rotr32(m[i-15],18) ^ (m[i-15] >> 3);
        uint32_t s1 = rotr32(m[i-2],17) ^ rotr32(m[i-2],19) ^ (m[i-2] >> 10);
        m[i] = m[i-16] + s0 + m[i-7] + s1;
    }

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        uint32_t S1 = rotr32(e,6) ^ rotr32(e,11) ^ rotr32(e,25);
        uint32_t ch = (e & f) ^ ((~e) & g);
        uint32_t temp1 = h + S1 + ch + k256[i] + m[i];
        uint32_t S0 = rotr32(a,2) ^ rotr32(a,13) ^ rotr32(a,22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temp2 = S0 + maj;

        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
    ctx->state[5] += f;
    ctx->state[6] += g;
    ctx->state[7] += h;
}

static void sha256_init(sha256_ctx *ctx) {
    ctx->datalen = 0;
    ctx->bitlen = 0;
    ctx->state[0] = 0x6a09e667UL;
    ctx->state[1] = 0xbb67ae85UL;
    ctx->state[2] = 0x3c6ef372UL;
    ctx->state[3] = 0xa54ff53aUL;
    ctx->state[4] = 0x510e527fUL;
    ctx->state[5] = 0x9b05688cUL;
    ctx->state[6] = 0x1f83d9abUL;
    ctx->state[7] = 0x5be0cd19UL;
}

static void sha256_update(sha256_ctx *ctx, const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ctx->data[ctx->datalen++] = data[i];
        if (ctx->datalen == 64) {
            sha256_transform(ctx, ctx->data);
            ctx->bitlen += 512;
            ctx->datalen = 0;
        }
    }
}

static void sha256_final(sha256_ctx *ctx, uint8_t hash[32]) {
    uint32_t i = ctx->datalen;

    /* Pad */
    if (ctx->datalen < 56) {
        ctx->data[i++] = 0x80;
        while (i < 56) ctx->data[i++] = 0x00;
    } else {
        ctx->data[i++] = 0x80;
        while (i < 64) ctx->data[i++] = 0x00;
        sha256_transform(ctx, ctx->data);
        memset(ctx->data, 0, 56);
    }

    /* Append length in bits as big-endian 64-bit */
    ctx->bitlen += (uint64_t)ctx->datalen * 8ULL;
    uint64_t bitlen = ctx->bitlen;
    ctx->data[56] = (uint8_t)((bitlen >> 56) & 0xFF);
    ctx->data[57] = (uint8_t)((bitlen >> 48) & 0xFF);
    ctx->data[58] = (uint8_t)((bitlen >> 40) & 0xFF);
    ctx->data[59] = (uint8_t)((bitlen >> 32) & 0xFF);
    ctx->data[60] = (uint8_t)((bitlen >> 24) & 0xFF);
    ctx->data[61] = (uint8_t)((bitlen >> 16) & 0xFF);
    ctx->data[62] = (uint8_t)((bitlen >> 8) & 0xFF);
    ctx->data[63] = (uint8_t)(bitlen & 0xFF);

    sha256_transform(ctx, ctx->data);

    /* Produce big-endian hash */
    for (i = 0; i < 4; ++i) {
        hash[i]      = (uint8_t)((ctx->state[0] >> (24 - i * 8)) & 0xFF);
        hash[i + 4]  = (uint8_t)((ctx->state[1] >> (24 - i * 8)) & 0xFF);
        hash[i + 8]  = (uint8_t)((ctx->state[2] >> (24 - i * 8)) & 0xFF);
        hash[i + 12] = (uint8_t)((ctx->state[3] >> (24 - i * 8)) & 0xFF);
        hash[i + 16] = (uint8_t)((ctx->state[4] >> (24 - i * 8)) & 0xFF);
        hash[i + 20] = (uint8_t)((ctx->state[5] >> (24 - i * 8)) & 0xFF);
        hash[i + 24] = (uint8_t)((ctx->state[6] >> (24 - i * 8)) & 0xFF);
        hash[i + 28] = (uint8_t)((ctx->state[7] >> (24 - i * 8)) & 0xFF);
    }
}

static void sha256_bytes(const uint8_t *data, size_t len, uint8_t out[32]) {
    sha256_ctx ctx;
    sha256_init(&ctx);
    sha256_update(&ctx, data, len);
    sha256_final(&ctx, out);
}

/* ------------------------------
 * Base64 encoding (single canonical implementation)
 * ------------------------------ */

static const char base64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded = malloc(output_length + 1);
    if (!encoded) return NULL;

    size_t i = 0, j = 0;
    while (i < input_length) {
        uint32_t a = i < input_length ? data[i++] : 0;
        uint32_t b = i < input_length ? data[i++] : 0;
        uint32_t c = i < input_length ? data[i++] : 0;

        uint32_t triple = (a << 16) | (b << 8) | c;

        encoded[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded[j++] = (i > input_length + 1) ? '=' : base64_table[(triple >> 6) & 0x3F];
        encoded[j++] = (i > input_length) ? '=' : base64_table[triple & 0x3F];
    }

    encoded[j] = '\0';
    return encoded;
}

/* ------------------------------
 * Read file binary (uses fseeko/ftello)
 * ------------------------------ */

static unsigned char *read_file_binary(const char *path, size_t *size_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    if (fseeko(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return NULL;
    }
    off_t off = ftello(fp);
    if (off < 0 || (unsigned long long)off > MAX_FILE_SIZE) {
        fprintf(stderr, "File too large (max 4 GiB): %s\n", path);
        fclose(fp);
        return NULL;
    }
    if (fseeko(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    size_t size = (size_t)off;
    unsigned char *buf = malloc(size ? size : 1); /* avoid malloc(0) */
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    size_t n = fread(buf, 1, size, fp);
    fclose(fp);

    if (n != size) {
        fprintf(stderr, "Short read error: %s\n", path);
        free(buf);
        return NULL;
    }

    *size_out = size;
    return buf;
}

/* ------------------------------
 * Global DB credentials
 * ------------------------------ */

const char *DB_USER;
const char *DB_PASS;
const char *DB_HOST;
const char *DB_NAME;

/* ------------------------------
 * Safe argument parser (returns 1 on success, 0 on failure)
 * ------------------------------ */

static int extract_value(const char *arg, const char *prefix, char *out, size_t outsz) {
    size_t plen = strlen(prefix);
    if (strncmp(arg, prefix, plen) != 0) {
        fprintf(stderr, "Invalid argument: %s\n", arg);
        return 0;
    }

    const char *start = arg + plen;
    const char *end = strrchr(start, '"');
    if (!end || end <= start) {
        fprintf(stderr, "Malformed argument: %s\n", arg);
        return 0;
    }

    size_t len = (size_t)(end - start);
    if (len >= outsz) len = outsz - 1;
    memcpy(out, start, len);
    out[len] = '\0';
    return 1;
}

/* ------------------------------
 * JSON string escaper (for filenames)
 * ------------------------------ */

static char *json_escape_string(const char *s) {
    size_t len = strlen(s);
    /* Worst-case expansion: every byte -> \u00XX (6 chars) */
    size_t max_out = len * 6 + 1;
    char *out = malloc(max_out);
    if (!out) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = c;
        } else if (c < 0x20) {
            /* control characters */
            int n = snprintf(out + j, max_out - j, "\\u%04x", c);
            if (n < 0) { free(out); return NULL; }
            j += (size_t)n;
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
    return out;
}

/* ------------------------------
 * URL encoder (percent-encoding)
 * ------------------------------ */

static char *url_encode(const char *s) {
    size_t len = strlen(s);
    char *out = malloc(len * 3 + 1);
    if (!out) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)s[i];
        if ((c >= 'A' && c <= 'Z') ||
            (c >= 'a' && c <= 'z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.' || c == '~') {
            out[j++] = (char)c;
        } else {
            int n = snprintf(out + j, 4, "%%%02X", c);
            if (n != 3) { free(out); return NULL; }
            j += 3;
        }
    }
    out[j] = '\0';
    return out;
}

/* ------------------------------
 * Deterministic ID generator:
 * sanitized filename + "_" + sha256hex(filename)
 * ------------------------------ */

static char *make_deterministic_id(const char *filename) {
    size_t len = strlen(filename);

    /* sanitized: replace non-alnum with '_' and lowercase */
    char *san = malloc(len + 1);
    if (!san) return NULL;
    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)filename[i];
        if (isalnum(c)) san[j++] = (char)tolower(c);
        else san[j++] = '_';
    }
    san[j] = '\0';

    /* compute sha256 of the original filename bytes */
    uint8_t hash[32];
    sha256_bytes((const uint8_t *)filename, len, hash);

    /* hex encode */
    char hash_hex[65];
    for (int i = 0; i < 32; ++i) {
        snprintf(hash_hex + i*2, 3, "%02x", hash[i]);
    }
    hash_hex[64] = '\0';

    /* final id: san + "_" + hash_hex */
    size_t out_len = strlen(san) + 1 + 64 + 1;
    char *out = malloc(out_len);
    if (!out) { free(san); return NULL; }
    snprintf(out, out_len, "%s_%s", san, hash_hex);
    free(san);
    return out;
}

/* ------------------------------
 * Config file loader
 * ------------------------------ */

static int load_config_file(const char *path,
                            char *user_buf, size_t user_sz,
                            char *pass_buf, size_t pass_sz,
                            char *host_buf, size_t host_sz,
                            char *name_buf, size_t name_sz)
{
    FILE *fp = fopen(path, "r");
    if (!fp) {
        fprintf(stderr, "Cannot open config file: %s\n", path);
        return 0;
    }

    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (strlen(line) < 3) continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = '\0';
        char *key = line;
        char *val = eq + 1;

        if (val[0] != '"') {
            fprintf(stderr, "Malformed config line (missing opening quote): %s\n", line);
            fclose(fp);
            return 0;
        }

        char *end = strrchr(val, '"');
        if (!end || end == val) {
            fprintf(stderr, "Malformed config line (missing closing quote): %s\n", line);
            fclose(fp);
            return 0;
        }

        size_t len = (size_t)(end - (val + 1));
        if (strcmp(key, "db_usr") == 0) {
            if (len >= user_sz) len = user_sz - 1;
            memcpy(user_buf, val + 1, len);
            user_buf[len] = '\0';
        } else if (strcmp(key, "db_passwd") == 0) {
            if (len >= pass_sz) len = pass_sz - 1;
            memcpy(pass_buf, val + 1, len);
            pass_buf[len] = '\0';
        } else if (strcmp(key, "db_hst") == 0) {
            if (len >= host_sz) len = host_sz - 1;
            memcpy(host_buf, val + 1, len);
            host_buf[len] = '\0';
        } else if (strcmp(key, "db_name") == 0) {
            if (len >= name_sz) len = name_sz - 1;
            memcpy(name_buf, val + 1, len);
            name_buf[len] = '\0';
        } else {
            /* unknown key: ignore but warn */
            fprintf(stderr, "Warning: unknown config key: %s\n", key);
        }
    }

    fclose(fp);
    return 1;
}

/* ------------------------------
 * Upload attachment
 * ------------------------------ */

static int upload_attachment(const char *filepath) {
    size_t filesize;
    unsigned char *filedata = read_file_binary(filepath, &filesize);
    if (!filedata) {
        fprintf(stderr, "Skipping unreadable or oversized file: %s\n", filepath);
        return 1;
    }

    char *b64 = base64_encode(filedata, filesize);
    free(filedata);
    if (!b64) return 1;

    const char *filename = strrchr(filepath, '/');
    filename = filename ? filename + 1 : filepath;

    char *escaped_name = json_escape_string(filename);
    if (!escaped_name) {
        free(b64);
        return 1;
    }

    char *det_id = NULL;
    char *det_id_url = NULL;

    if (USE_DETERMINISTIC_ID) {
        det_id = make_deterministic_id(filename);
        if (!det_id) {
            free(b64);
            free(escaped_name);
            return 1;
        }
        det_id_url = url_encode(det_id);
        if (!det_id_url) {
            free(b64);
            free(escaped_name);
            free(det_id);
            return 1;
        }
    }

    /* Conservative JSON sizing:
     * - base64 length
     * - escaped filename length
     * - if deterministic: include _id length
     * - add headroom for JSON punctuation
     */
    size_t json_size = strlen(b64) + strlen(escaped_name) + 512;
    if (det_id) json_size += strlen(det_id) + 64;

    char *json = malloc(json_size);
    if (!json) {
        free(b64);
        free(escaped_name);
        free(det_id);
        free(det_id_url);
        return 1;
    }

    if (USE_DETERMINISTIC_ID) {
        /* include _id field */
        int n = snprintf(json, json_size,
            "{ \"_id\": \"%s\", \"_attachments\": { \"%s\": { \"content_type\": \"application/octet-stream\", \"data\": \"%s\" } } }",
            det_id, escaped_name, b64);
        if (n < 0 || (size_t)n >= json_size) {
            fprintf(stderr, "JSON construction overflow\n");
            free(json);
            free(b64);
            free(escaped_name);
            free(det_id);
            free(det_id_url);
            return 1;
        }
    } else {
        int n = snprintf(json, json_size,
            "{ \"_attachments\": { \"%s\": { \"content_type\": \"application/octet-stream\", \"data\": \"%s\" } } }",
            escaped_name, b64);
        if (n < 0 || (size_t)n >= json_size) {
            fprintf(stderr, "JSON construction overflow\n");
            free(json);
            free(b64);
            free(escaped_name);
            return 1;
        }
    }

    free(b64);
    free(escaped_name);

    char url[2048];
    size_t hlen = strlen(DB_HOST);
    const char *sep = (hlen > 0 && DB_HOST[hlen - 1] == '/') ? "" : "/";

    if (USE_DETERMINISTIC_ID) {
        /* PUT to DB/ID */
        if (snprintf(url, sizeof(url), "%s%s%s/%s", DB_HOST, sep, DB_NAME, det_id_url) >= (int)sizeof(url)) {
            fprintf(stderr, "URL too long\n");
            free(json);
            free(det_id);
            free(det_id_url);
            return 1;
        }
    } else {
        /* POST to DB */
        if (snprintf(url, sizeof(url), "%s%s%s", DB_HOST, sep, DB_NAME) >= (int)sizeof(url)) {
            fprintf(stderr, "URL too long\n");
            free(json);
            return 1;
        }
    }

    /* free det_id_url/det_id now that url is built */
    free(det_id_url);
    free(det_id);

    printf("Uploading: %s\n", filepath);

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(json);
        return 1;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);

    /* timeouts to avoid hung workers */
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);

    if (USE_DETERMINISTIC_ID)
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    else
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

    if (DB_USER && DB_PASS) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, DB_USER);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, DB_PASS);
    }

    CURLcode res = curl_easy_perform(curl);

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    free(json);

    if (res != CURLE_OK) {
        fprintf(stderr, "curl error: %s\n", curl_easy_strerror(res));
        return 1;
    }

    return 0;
}

/* ------------------------------
 * Work queue for parallel uploads
 * ------------------------------ */

typedef struct job {
    char *path;
    struct job *next;
} job_t;

static job_t *queue_head = NULL;
static job_t *queue_tail = NULL;

static pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

static int workers_running = 1;

static void queue_push(const char *path) {
    job_t *j = malloc(sizeof(job_t));
    if (!j) return;
    j->path = strdup(path);
    j->next = NULL;

    pthread_mutex_lock(&queue_mutex);
    if (queue_tail)
        queue_tail->next = j;
    else
        queue_head = j;
    queue_tail = j;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

static char *queue_pop(void) {
    pthread_mutex_lock(&queue_mutex);
    while (workers_running && queue_head == NULL)
        pthread_cond_wait(&queue_cond, &queue_mutex);

    if (!workers_running && queue_head == NULL) {
        pthread_mutex_unlock(&queue_mutex);
        return NULL;
    }

    job_t *j = queue_head;
    queue_head = j->next;
    if (!queue_head) queue_tail = NULL;
    pthread_mutex_unlock(&queue_mutex);

    char *path = j->path;
    free(j);
    return path;
}

static void *worker_thread(void *arg) {
    (void)arg;
    while (1) {
        char *path = queue_pop();
        if (!path) break;
        upload_attachment(path);
        free(path);
    }
    return NULL;
}

/* ------------------------------
 * Recursive directory walker
 * ------------------------------ */

static int upload_recursive_parallel(const char *root, int threads) {
    if (threads < 1 || threads > MAX_THREADS) {
        fprintf(stderr, "Invalid thread count (max %d)\n", MAX_THREADS);
        return 1;
    }

    pthread_t *tids = malloc(sizeof(pthread_t) * (size_t)threads);
    if (!tids) {
        fprintf(stderr, "Failed to allocate thread array\n");
        return 1;
    }

    for (int i = 0; i < threads; ++i) {
        if (pthread_create(&tids[i], NULL, worker_thread, NULL) != 0) {
            fprintf(stderr, "Failed to create thread %d\n", i);
            /* signal shutdown to already created threads */
            pthread_mutex_lock(&queue_mutex);
            workers_running = 0;
            pthread_cond_broadcast(&queue_cond);
            pthread_mutex_unlock(&queue_mutex);
            for (int j = 0; j < i; ++j) pthread_join(tids[j], NULL);
            free(tids);
            return 1;
        }
    }

    char *paths[] = { (char *)root, NULL };
    FTS *fts = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, NULL);
    if (!fts) {
        fprintf(stderr, "fts_open failed\n");
        pthread_mutex_lock(&queue_mutex);
        workers_running = 0;
        pthread_cond_broadcast(&queue_cond);
        pthread_mutex_unlock(&queue_mutex);
        for (int i = 0; i < threads; ++i) pthread_join(tids[i], NULL);
        free(tids);
        return 1;
    }

    FTSENT *ent;
    while ((ent = fts_read(fts)) != NULL) {
        if (ent->fts_info == FTS_F) {
            queue_push(ent->fts_path);
        }
    }

    fts_close(fts);

    pthread_mutex_lock(&queue_mutex);
    workers_running = 0;
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    for (int i = 0; i < threads; ++i) pthread_join(tids[i], NULL);
    free(tids);
    return 0;
}

/* ------------------------------
 * Main
 * ------------------------------ */

int main(int argc, char *argv[]) {
    static char user_buf[256], pass_buf[256], host_buf[512], name_buf[256];

    int argi = 1;

    /* CONFIG MODE FIRST */
    if (argc >= 3 && strcmp(argv[1], "-c") == 0) {
        if (!load_config_file(argv[2],
                              user_buf, sizeof(user_buf),
                              pass_buf, sizeof(pass_buf),
                              host_buf, sizeof(host_buf),
                              name_buf, sizeof(name_buf))) {
            return 1;
        }

        DB_USER = user_buf;
        DB_PASS = pass_buf;
        DB_HOST = host_buf;
        DB_NAME = name_buf;

        argi = 3;

        if (argc == 3) {
            printf("Loaded config from %s\n", argv[2]);
            return 0;
        }
    }

    /* STRICT ARGUMENT MODE */
    if (argi == 1) {
        if (argc < 7) {
            printf("Usage:\n");
            printf("  %s -c <configfile> [-n]\n", argv[0]);
            printf("  %s 'db_usr=\"user\"' 'db_passwd=\"pw\"' 'db_hst=\"url\"' 'db_name=\"dbname\"' [-n] <file>\n", argv[0]);
            printf("  %s 'db_usr=\"user\"' 'db_passwd=\"pw\"' 'db_hst=\"url\"' 'db_name=\"dbname\"' [-n] -p N -r <folder>\n", argv[0]);
            printf("\n  -n  Use deterministic document IDs based on sanitized filename + SHA-256\n");
            return 1;
        }

        if (!extract_value(argv[1], "db_usr=\"", user_buf, sizeof(user_buf)) ||
            !extract_value(argv[2], "db_passwd=\"", pass_buf, sizeof(pass_buf)) ||
            !extract_value(argv[3], "db_hst=\"", host_buf, sizeof(host_buf)) ||
            !extract_value(argv[4], "db_name=\"", name_buf, sizeof(name_buf))) {

            fprintf(stderr, "Argument parsing failed\n");
            return 1;
        }

        DB_USER = user_buf;
        DB_PASS = pass_buf;
        DB_HOST = host_buf;
        DB_NAME = name_buf;

        argi = 5;
    }

    /* Parse -n after credentials are known */
    for (int i = argi; i < argc; ++i) {
        if (strcmp(argv[i], "-n") == 0) {
            USE_DETERMINISTIC_ID = 1;
            /* remove -n from argv so later arg counting works */
            for (int j = i; j < argc - 1; ++j) argv[j] = argv[j + 1];
            argc--;
            break;
        }
    }

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        fprintf(stderr, "curl_global_init failed\n");
        return 1;
    }

    int ret = 1;

    /* SINGLE FILE MODE */
    if (argc - argi == 1) {
        ret = upload_attachment(argv[argi]);
        curl_global_cleanup();
        return ret;
    }

    /* PARALLEL RECURSIVE MODE */
    if (argc - argi == 4 &&
        strcmp(argv[argi], "-p") == 0 &&
        strcmp(argv[argi + 2], "-r") == 0) {

        int threads = atoi(argv[argi + 1]);
        ret = upload_recursive_parallel(argv[argi + 3], threads);
        curl_global_cleanup();
        return ret;
    }

    printf("Invalid arguments.\n");
    curl_global_cleanup();
    return 1;
}
