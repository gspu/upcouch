/*
 * upcouch.c (refactored, modernized)
 *
 * Uses system OpenSSL for SHA-256 and libcurl for HTTP.
 * Deterministic mode (-n) will NOT update existing documents:
 *  - If doc exists -> skip upload
 *  - If doc does not exist -> create it (PUT)
 *  - If concurrent create returns 409 -> treat as created and skip
 *
 * Build (example):
 *   cc -std=c11 -Wall -Wextra -O2 -I/usr/local/include upcouch.c -pthread -L/usr/local/lib -lcurl -lcrypto -lpthread -o upcouch
 *
 * Note: Ensure libcurl and OpenSSL development headers are installed.
 */

#define _POSIX_C_SOURCE 200809L

#include <ctype.h>
#include <errno.h>
#include <fts.h>
#include <inttypes.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <curl/curl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------
 * Globals / configuration
 * ------------------------------ */

#define MAX_FILE_SIZE 4294967296ULL   /* 4 GiB */
#define MAX_THREADS   64

static int   USE_DETERMINISTIC_ID = 0;
static const char *DB_USER = NULL;
static const char *DB_PASS = NULL;
static const char *DB_HOST = NULL;
static const char *DB_NAME = NULL;

/* ------------------------------
 * Forward declarations
 * ------------------------------ */

static int   extract_value(const char *arg, const char *prefix, char *out, size_t outsz);
static char *json_escape_string(const char *s);
static char *url_encode(const char *s);
static char *make_deterministic_id(const char *filename);
static unsigned char *read_file_binary(const char *path, size_t *size_out);
static char *base64_encode(const unsigned char *in, size_t len);
static char *http_get_body(const char *url, const char *user, const char *pass, long *http_code);
static int   upload_attachment(const char *filepath);
static int   load_config_file(const char *path,
                              char *user_buf, size_t user_sz,
                              char *pass_buf, size_t pass_sz,
                              char *host_buf, size_t host_sz,
                              char *name_buf, size_t name_sz);
static int   upload_recursive_parallel(const char *root, int threads);

/* ------------------------------
 * Base64 (canonical, correct)
 * ------------------------------ */

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char *base64_encode(const unsigned char *in, size_t len) {
    size_t out_len = 4 * ((len + 2) / 3);
    char *out = malloc(out_len + 1);
    if (!out) return NULL;

    size_t i = 0, j = 0;
    while (i + 2 < len) {
        uint32_t triple = ((uint32_t)in[i] << 16) |
                          ((uint32_t)in[i + 1] << 8) |
                          (uint32_t)in[i + 2];
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        out[j++] = b64_table[(triple >> 6) & 0x3F];
        out[j++] = b64_table[triple & 0x3F];
        i += 3;
    }

    if (i < len) {
        uint32_t a = in[i++];
        uint32_t b = (i < len) ? in[i++] : 0;
        uint32_t triple = (a << 16) | (b << 8);
        out[j++] = b64_table[(triple >> 18) & 0x3F];
        out[j++] = b64_table[(triple >> 12) & 0x3F];
        if ((len % 3) == 2) {
            out[j++] = b64_table[(triple >> 6) & 0x3F];
            out[j++] = '=';
        } else {
            out[j++] = '=';
            out[j++] = '=';
        }
    }

    out[j] = '\0';
    return out;
}

/* ------------------------------
 * Read file binary (fseeko/ftello)
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
        fclose(fp);
        return NULL;
    }
    if (fseeko(fp, 0, SEEK_SET) != 0) {
        fclose(fp);
        return NULL;
    }

    size_t size = (size_t)off;
    unsigned char *buf = malloc(size ? size : 1);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    size_t n = fread(buf, 1, size, fp);
    fclose(fp);
    if (n != size) {
        free(buf);
        return NULL;
    }

    *size_out = size;
    return buf;
}

/* ------------------------------
 * JSON escaping (safe)
 * ------------------------------ */

static char *json_escape_string(const char *s) {
    if (!s) return NULL;
    size_t len = strlen(s);
    size_t max_out = len * 6 + 1; /* worst-case: every byte -> \u00XX */
    char *out = malloc(max_out);
    if (!out) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = c;
        } else if (c == '\b') {
            out[j++] = '\\';
            out[j++] = 'b';
        } else if (c == '\f') {
            out[j++] = '\\';
            out[j++] = 'f';
        } else if (c == '\n') {
            out[j++] = '\\';
            out[j++] = 'n';
        } else if (c == '\r') {
            out[j++] = '\\';
            out[j++] = 'r';
        } else if (c == '\t') {
            out[j++] = '\\';
            out[j++] = 't';
        } else if (c < 0x20) {
            int n = snprintf(out + j, max_out - j, "\\u%04x", c);
            if (n < 0) {
                free(out);
                return NULL;
            }
            j += (size_t)n;
        } else {
            out[j++] = (char)c;
        }
    }
    out[j] = '\0';
    return out;
}

/* ------------------------------
 * URL encode (percent-encode)
 * ------------------------------ */

static char *url_encode(const char *s) {
    if (!s) return NULL;
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
            /* 3 chars + NUL, snprintf always returns 3 here on sane libc */
            snprintf(out + j, 4, "%%%02X", c);
            j += 3;
        }
    }
    out[j] = '\0';
    return out;
}

/* ------------------------------
 * Deterministic ID: sanitized filename + "_" + sha256hex(filename)
 * Uses OpenSSL SHA256()
 * ------------------------------ */

static char *make_deterministic_id(const char *filename) {
    if (!filename) return NULL;
    size_t len = strlen(filename);

    char *san = malloc(len + 1);
    if (!san) return NULL;

    size_t j = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = (unsigned char)filename[i];
        san[j++] = isalnum(c) ? (char)tolower(c) : '_';
    }
    san[j] = '\0';

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char *)filename, len, hash);

    char hash_hex[SHA256_DIGEST_LENGTH * 2 + 1];
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        snprintf(hash_hex + i * 2, 3, "%02x", hash[i]);
    }
    hash_hex[SHA256_DIGEST_LENGTH * 2] = '\0';

    size_t out_len = strlen(san) + 1 + (SHA256_DIGEST_LENGTH * 2) + 1;
    char *out = malloc(out_len);
    if (!out) {
        free(san);
        return NULL;
    }

    snprintf(out, out_len, "%s_%s", san, hash_hex);
    free(san);
    return out;
}

/* ------------------------------
 * Simple HTTP GET helper (returns malloc'd body or NULL)
 * ------------------------------ */

struct membuf {
    char  *ptr;
    size_t len;
};

static size_t write_cb(void *data, size_t size, size_t nmemb, void *userp) {
    size_t realsz = size * nmemb;
    struct membuf *m = (struct membuf *)userp;

    char *tmp = realloc(m->ptr, m->len + realsz + 1);
    if (!tmp) return 0;

    m->ptr = tmp;
    memcpy(m->ptr + m->len, data, realsz);
    m->len += realsz;
    m->ptr[m->len] = '\0';
    return realsz;
}

static char *http_get_body(const char *url, const char *user, const char *pass, long *http_code) {
    if (!url) return NULL;

    CURL *curl = curl_easy_init();
    if (!curl) return NULL;

    struct membuf m = { malloc(1), 0 };
    if (!m.ptr) {
        curl_easy_cleanup(curl);
        return NULL;
    }
    m.ptr[0] = '\0';

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &m);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 30L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    if (user && pass) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, user);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, pass);
    }

    CURLcode res = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (http_code) *http_code = code;

    if (res != CURLE_OK) {
        free(m.ptr);
        m.ptr = NULL;
    }

    curl_easy_cleanup(curl);
    return m.ptr;
}

/* ------------------------------
 * Config loader
 * ------------------------------ */

static int load_config_file(const char *path,
                            char *user_buf, size_t user_sz,
                            char *pass_buf, size_t pass_sz,
                            char *host_buf, size_t host_sz,
                            char *name_buf, size_t name_sz) {
    if (!path) return 0;

    FILE *fp = fopen(path, "r");
    if (!fp) return 0;

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
        if (val[0] != '"') continue;

        char *end = strrchr(val, '"');
        if (!end || end == val) continue;

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
        }
    }

    fclose(fp);
    return 1;
}

/* ------------------------------
 * Per-id in-process lock (simple)
 * ------------------------------ */

typedef struct idnode {
    char *id;
    struct idnode *next;
} idnode_t;

static idnode_t *id_head = NULL;
static pthread_mutex_t id_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t  id_cond  = PTHREAD_COND_INITIALIZER;

static void acquire_id_lock(const char *id) {
    if (!id) return;

    pthread_mutex_lock(&id_mutex);
    for (;;) {
        idnode_t *cur = id_head;
        int found = 0;
        while (cur) {
            if (strcmp(cur->id, id) == 0) {
                found = 1;
                break;
            }
            cur = cur->next;
        }

        if (!found) {
            idnode_t *n = malloc(sizeof(idnode_t));
            if (!n) break; /* allocation failure: proceed without lock */

            n->id = strdup(id);
            if (!n->id) {
                free(n);
                break;
            }

            n->next = id_head;
            id_head = n;
            break;
        }

        pthread_cond_wait(&id_cond, &id_mutex);
    }
    pthread_mutex_unlock(&id_mutex);
}

static void release_id_lock(const char *id) {
    if (!id) return;

    pthread_mutex_lock(&id_mutex);
    idnode_t **pp = &id_head;
    while (*pp) {
        if (strcmp((*pp)->id, id) == 0) {
            idnode_t *rem = *pp;
            *pp = rem->next;
            free(rem->id);
            free(rem);
            pthread_cond_broadcast(&id_cond);
            break;
        }
        pp = &(*pp)->next;
    }
    pthread_mutex_unlock(&id_mutex);
}

/* ------------------------------
 * Curl JSON helper
 * ------------------------------ */

static int couch_send_json(const char *url,
                           const char *json,
                           const char *method, /* "POST" or "PUT" */
                           const char *user,
                           const char *pass,
                           long *code_out,
                           const char *err_prefix) {
    CURL *curl = curl_easy_init();
    if (!curl) return 1;

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
    curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

    if (method && strcmp(method, "PUT") == 0) {
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
    } else {
        curl_easy_setopt(curl, CURLOPT_POST, 1L);
    }

    if (user && pass) {
        curl_easy_setopt(curl, CURLOPT_USERNAME, user);
        curl_easy_setopt(curl, CURLOPT_PASSWORD, pass);
    }

    CURLcode cres = curl_easy_perform(curl);
    long code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
    if (code_out) *code_out = code;

    int result = 1;
    if (cres != CURLE_OK) {
        fprintf(stderr, "%s: %s\n", err_prefix ? err_prefix : "curl error",
                curl_easy_strerror(cres));
        result = 1;
    } else if (code >= 200 && code < 300) {
        result = 0;
    } else {
        fprintf(stderr, "%s HTTP error: %ld\n",
                err_prefix ? err_prefix : "HTTP", code);
        result = 1;
    }

    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return result;
}

/* ------------------------------
 * Upload attachment (main logic)
 * ------------------------------ */

static int upload_attachment(const char *filepath) {
    if (!filepath) return 1;

    int result = 1;

    size_t filesize = 0;
    unsigned char *filedata = read_file_binary(filepath, &filesize);
    if (!filedata) {
        fprintf(stderr, "Skipping unreadable or oversized file: %s\n", filepath);
        return 1;
    }

    char *b64 = base64_encode(filedata, filesize);
    if (!b64) {
        free(filedata);
        return 1;
    }

    const char *filename = strrchr(filepath, '/');
    filename = filename ? filename + 1 : filepath;

    char *escaped_name = json_escape_string(filename);
    if (!escaped_name) {
        free(filedata);
        free(b64);
        return 1;
    }

    char *det_id = NULL;
    char *det_id_url = NULL;

    if (USE_DETERMINISTIC_ID) {
        det_id = make_deterministic_id(filename);
        if (!det_id) {
            free(filedata);
            free(b64);
            free(escaped_name);
            return 1;
        }
        det_id_url = url_encode(det_id);
        if (!det_id_url) {
            free(filedata);
            free(b64);
            free(escaped_name);
            free(det_id);
            return 1;
        }
    }

    /* Build base URL dynamically to avoid fixed buffer overflow */
    size_t host_len = strlen(DB_HOST ? DB_HOST : "");
    const char *sep = (host_len > 0 && DB_HOST[host_len - 1] == '/') ? "" : "/";

    char *base_url = NULL;
    if (USE_DETERMINISTIC_ID) {
        size_t need = strlen(DB_HOST) + strlen(sep) + strlen(DB_NAME) + 1 + strlen(det_id_url) + 1;
        base_url = malloc(need);
        if (!base_url) {
            free(filedata);
            free(b64);
            free(escaped_name);
            free(det_id);
            free(det_id_url);
            return 1;
        }
        if (snprintf(base_url, need, "%s%s%s/%s", DB_HOST, sep, DB_NAME, det_id_url) < 0) {
            free(base_url);
            free(filedata);
            free(b64);
            free(escaped_name);
            free(det_id);
            free(det_id_url);
            return 1;
        }
    } else {
        size_t need = strlen(DB_HOST) + strlen(sep) + strlen(DB_NAME) + 1;
        base_url = malloc(need);
        if (!base_url) {
            free(filedata);
            free(b64);
            free(escaped_name);
            return 1;
        }
        if (snprintf(base_url, need, "%s%s%s", DB_HOST, sep, DB_NAME) < 0) {
            free(base_url);
            free(filedata);
            free(b64);
            free(escaped_name);
            return 1;
        }
    }

    printf("Uploading: %s\n", filepath);

    if (!USE_DETERMINISTIC_ID) {
        /* Non-deterministic: POST JSON with base64 attachment */
        size_t json_size = strlen(b64) + strlen(escaped_name) + 512;
        char *json = malloc(json_size);
        if (!json) {
            free(base_url);
            free(filedata);
            free(b64);
            free(escaped_name);
            return 1;
        }

        int n = snprintf(json, json_size,
                         "{ \"_attachments\": { \"%s\": { \"content_type\": \"application/octet-stream\", \"data\": \"%s\" } } }",
                         escaped_name, b64);
        if (n < 0 || (size_t)n >= json_size) {
            fprintf(stderr, "JSON construction overflow\n");
            free(json);
            free(base_url);
            free(filedata);
            free(b64);
            free(escaped_name);
            return 1;
        }

        long code = 0;
        int rc = couch_send_json(base_url, json, "POST",
                                 DB_USER, DB_PASS, &code, "curl error");
        if (rc == 0) result = 0;

        free(json);
        free(base_url);
        free(filedata);
        free(b64);
        free(escaped_name);
        return result;
    }

    /* Deterministic mode: do not update existing documents; skip if exists */
    acquire_id_lock(det_id);

    long get_code = 0;
    char *body = http_get_body(base_url, DB_USER, DB_PASS, &get_code);
    if (body && get_code == 200) {
        printf("Document %s already exists — skipping upload.\n", det_id);
        free(body);
        result = 0;
        release_id_lock(det_id);
        goto det_cleanup;
    }
    if (body) {
        free(body);
        body = NULL;
    }

    /* Attempt to create document via PUT (no update) */
    {
        size_t json_size = strlen(b64) + strlen(escaped_name) + strlen(det_id) + 512;
        char *json = malloc(json_size);
        if (!json) {
            result = 1;
            release_id_lock(det_id);
            goto det_cleanup;
        }

        int n = snprintf(json, json_size,
                         "{ \"_id\": \"%s\", \"_attachments\": { \"%s\": { \"content_type\": \"application/octet-stream\", \"data\": \"%s\" } } }",
                         det_id, escaped_name, b64);
        if (n < 0 || (size_t)n >= json_size) {
            fprintf(stderr, "JSON construction overflow\n");
            free(json);
            result = 1;
            release_id_lock(det_id);
            goto det_cleanup;
        }

        CURL *curl = curl_easy_init();
        if (!curl) {
            free(json);
            result = 1;
            release_id_lock(det_id);
            goto det_cleanup;
        }

        struct curl_slist *headers = NULL;
        headers = curl_slist_append(headers, "Content-Type: application/json");

        curl_easy_setopt(curl, CURLOPT_URL, base_url);
        curl_easy_setopt(curl, CURLOPT_CUSTOMREQUEST, "PUT");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 300L);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        if (DB_USER && DB_PASS) {
            curl_easy_setopt(curl, CURLOPT_USERNAME, DB_USER);
            curl_easy_setopt(curl, CURLOPT_PASSWORD, DB_PASS);
        }

        CURLcode cres = curl_easy_perform(curl);
        long code = 0;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);

        if (cres != CURLE_OK) {
            fprintf(stderr, "curl error on PUT: %s\n", curl_easy_strerror(cres));
            result = 1;
        } else if (code == 201 || code == 202 || code == 200) {
            result = 0;
        } else if (code == 409) {
            printf("Document %s created by another process (skipping upload).\n", det_id);
            result = 0;
        } else {
            fprintf(stderr, "PUT failed: HTTP %ld\n", code);
            result = 1;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
        free(json);
        release_id_lock(det_id);
    }

det_cleanup:
    free(base_url);
    free(filedata);
    free(b64);
    free(escaped_name);
    free(det_id_url);
    free(det_id);
    return result;
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
static pthread_cond_t  queue_cond  = PTHREAD_COND_INITIALIZER;
static int             workers_running = 1;

static void queue_push(const char *path) {
    job_t *j = malloc(sizeof(job_t));
    if (!j) return;

    j->path = strdup(path);
    if (!j->path) {
        free(j);
        return;
    }
    j->next = NULL;

    pthread_mutex_lock(&queue_mutex);
    if (queue_tail) {
        queue_tail->next = j;
    } else {
        queue_head = j;
    }
    queue_tail = j;
    pthread_cond_signal(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);
}

static char *queue_pop(void) {
    pthread_mutex_lock(&queue_mutex);
    while (workers_running && queue_head == NULL) {
        pthread_cond_wait(&queue_cond, &queue_mutex);
    }
    if (!workers_running && queue_head == NULL) {
        pthread_mutex_unlock(&queue_mutex);
        return NULL;
    }

    job_t *j = queue_head;
    queue_head = j->next;
    if (!queue_head) queue_tail = NULL;

    pthread_mutex_unlock(&queue_mutex);

    char *p = j->path;
    free(j);
    return p;
}

static void *worker_thread(void *arg) {
    (void)arg;
    for (;;) {
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
    if (!root) return 1;
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
        fprintf(stderr, "fts_open failed: %s\n", strerror(errno));
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
 * Helper: extract_value (argument parsing)
 * ------------------------------ */

static int extract_value(const char *arg, const char *prefix, char *out, size_t outsz) {
    size_t plen = strlen(prefix);
    if (strncmp(arg, prefix, plen) != 0) return 0;

    const char *start = arg + plen;
    const char *end = strrchr(start, '"');
    if (!end || end <= start) return 0;

    size_t len = (size_t)(end - start);
    if (len >= outsz) len = outsz - 1;

    memcpy(out, start, len);
    out[len] = '\0';
    return 1;
}

/* ------------------------------
 * Main
 * ------------------------------ */

int main(int argc, char *argv[]) {
    static char user_buf[256];
    static char pass_buf[256];
    static char host_buf[1024];
    static char name_buf[256];

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
            printf("\n  -n  Use deterministic document IDs based on sanitized filename + SHA-256 (skip existing docs)\n");
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
            for (int j = i; j < argc - 1; ++j) {
                argv[j] = argv[j + 1];
            }
            argc--;
            break;
        }
    }

    if (!DB_HOST || !DB_NAME) {
        fprintf(stderr, "DB host and name must be provided.\n");
        return 1;
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
