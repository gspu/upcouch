#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fts.h>
#include <pthread.h>

#define MAX_FILE_SIZE 4294967296ULL   // 4 GiB
#define MAX_THREADS   64

// ------------------------------
// Base64 encoding
// ------------------------------
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

char *base64_encode(const unsigned char *data, size_t input_length) {
    size_t output_length = 4 * ((input_length + 2) / 3);
    char *encoded = malloc(output_length + 1);
    if (!encoded) return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < input_length;) {
        uint32_t a = i < input_length ? data[i++] : 0;
        uint32_t b = i < input_length ? data[i++] : 0;
        uint32_t c = i < input_length ? data[i++] : 0;

        uint32_t triple = (a << 16) | (b << 8) | c;

        encoded[j++] = b64_table[(triple >> 18) & 0x3F];
        encoded[j++] = b64_table[(triple >> 12) & 0x3F];
        encoded[j++] = (i > input_length + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        encoded[j++] = (i > input_length) ? '=' : b64_table[triple & 0x3F];
    }

    encoded[j] = '\0';
    return encoded;
}

// ------------------------------
// Read file binary
// ------------------------------
unsigned char *read_file_binary(const char *path, size_t *size_out) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return NULL;

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    rewind(fp);

    if (size < 0 || (unsigned long long)size > MAX_FILE_SIZE) {
        fprintf(stderr, "File too large (max 4 GiB): %s\n", path);
        fclose(fp);
        return NULL;
    }

    unsigned char *buf = malloc(size);
    if (!buf) {
        fclose(fp);
        return NULL;
    }

    size_t n = fread(buf, 1, size, fp);
    fclose(fp);

    if (n != (size_t)size) {
        fprintf(stderr, "Short read error: %s\n", path);
        free(buf);
        return NULL;
    }

    *size_out = size;
    return buf;
}

// ------------------------------
// Global DB credentials
// ------------------------------
const char *DB_USER;
const char *DB_PASS;
const char *DB_HOST;
const char *DB_NAME;

// ------------------------------
// Safe argument parser (NO exit())
// ------------------------------
int extract_value(const char *arg, const char *prefix, char *out, size_t outsz) {
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

    size_t len = end - start;
    if (len >= outsz) len = outsz - 1;

    memcpy(out, start, len);
    out[len] = 0;

    return 1;
}

// ------------------------------
// JSON string escaper (for filenames)
// ------------------------------
static char *json_escape_string(const char *s) {
    size_t len = strlen(s);
    size_t max_out = len * 6 + 1;
    char *out = malloc(max_out);
    if (!out) return NULL;

    size_t i, j = 0;
    for (i = 0; i < len; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '"' || c == '\\') {
            out[j++] = '\\';
            out[j++] = c;
        } else if (c < 0x20) {
            snprintf(out + j, max_out - j, "\\u%04x", c);
            j += 6;
        } else {
            out[j++] = c;
        }
    }
    out[j] = '\0';
    return out;
}

// ------------------------------
// Config file loader
// ------------------------------
int load_config_file(const char *path,
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
        if (nl) *nl = 0;

        if (strlen(line) < 3)
            continue;

        char *eq = strchr(line, '=');
        if (!eq) continue;

        *eq = 0;
        char *key = line;
        char *val = eq + 1;

        if (val[0] != '"') {
            fprintf(stderr, "Malformed config line: %s\n", line);
            fclose(fp);
            return 0;
        }

        char *end = strrchr(val, '"');
        if (!end || end == val) {
            fprintf(stderr, "Malformed config line: %s\n", line);
            fclose(fp);
            return 0;
        }

        size_t len = end - (val + 1);

        if (strcmp(key, "db_usr") == 0) {
            if (len >= user_sz) len = user_sz - 1;
            memcpy(user_buf, val + 1, len);
            user_buf[len] = 0;
        }
        else if (strcmp(key, "db_passwd") == 0) {
            if (len >= pass_sz) len = pass_sz - 1;
            memcpy(pass_buf, val + 1, len);
            pass_buf[len] = 0;
        }
        else if (strcmp(key, "db_hst") == 0) {
            if (len >= host_sz) len = host_sz - 1;
            memcpy(host_buf, val + 1, len);
            host_buf[len] = 0;
        }
        else if (strcmp(key, "db_name") == 0) {
            if (len >= name_sz) len = name_sz - 1;
            memcpy(name_buf, val + 1, len);
            name_buf[len] = 0;
        }
    }

    fclose(fp);
    return 1;
}

// ------------------------------
// Upload attachment
// ------------------------------
int upload_attachment(const char *filepath) {
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

    size_t json_size = strlen(b64) + strlen(escaped_name) + 200;
    char *json = malloc(json_size);
    if (!json) {
        free(b64);
        free(escaped_name);
        return 1;
    }

    snprintf(json, json_size,
        "{ \"_attachments\": { \"%s\": { \"content_type\": \"application/octet-stream\", \"data\": \"%s\" } } }",
        escaped_name, b64
    );

    free(b64);
    free(escaped_name);

    char url[1024];
    size_t hlen = strlen(DB_HOST);
    const char *sep = (hlen > 0 && DB_HOST[hlen - 1] == '/') ? "" : "/";
    snprintf(url, sizeof(url), "%s%s%s", DB_HOST, sep, DB_NAME);

    printf("Uploading: %s\n", filepath);

    CURL *curl = curl_easy_init();
    if (!curl) {
        free(json);
        return 1;
    }

    struct curl_slist *headers = NULL;
    headers = curl_slist_append(headers, "Content-Type: application/json");

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_POST, 1L);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, json);

    curl_easy_setopt(curl, CURLOPT_USERNAME, DB_USER);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, DB_PASS);

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

// ------------------------------
// Work queue for parallel uploads
// ------------------------------
typedef struct job {
    char *path;
    struct job *next;
} job_t;

job_t *queue_head = NULL;
job_t *queue_tail = NULL;

pthread_mutex_t queue_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t queue_cond = PTHREAD_COND_INITIALIZER;

int workers_running = 1;

// Push job
void queue_push(const char *path) {
    job_t *j = malloc(sizeof(job_t));
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

// Pop job
char *queue_pop() {
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

// Worker thread
void *worker_thread(void *arg) {
    (void)arg;

    while (1) {
        char *path = queue_pop();
        if (!path) break;

        upload_attachment(path);
        free(path);
    }
    return NULL;
}

// ------------------------------
// Recursive directory walker
// ------------------------------
int upload_recursive_parallel(const char *root, int threads) {

    if (threads < 1 || threads > MAX_THREADS) {
        fprintf(stderr, "Invalid thread count (max %d)\n", MAX_THREADS);
        return 1;
    }

    pthread_t *tids = malloc(sizeof(pthread_t) * threads);
    if (!tids) {
        fprintf(stderr, "Failed to allocate thread array\n");
        return 1;
    }

    for (int i = 0; i < threads; i++)
        pthread_create(&tids[i], NULL, worker_thread, NULL);

    char *paths[] = { (char *)root, NULL };
    FTS *fts = fts_open(paths, FTS_NOCHDIR | FTS_PHYSICAL, NULL);
    if (!fts) {
        fprintf(stderr, "fts_open failed\n");
        pthread_mutex_lock(&queue_mutex);
        workers_running = 0;
        pthread_cond_broadcast(&queue_cond);
        pthread_mutex_unlock(&queue_mutex);
        for (int i = 0; i < threads; i++)
            pthread_join(tids[i], NULL);
        free(tids);
        return 1;
    }

    FTSENT *ent;
    while ((ent = fts_read(fts)) != NULL) {
        if (ent->fts_info == FTS_F)
            queue_push(ent->fts_path);
    }

    fts_close(fts);

    pthread_mutex_lock(&queue_mutex);
    workers_running = 0;
    pthread_cond_broadcast(&queue_cond);
    pthread_mutex_unlock(&queue_mutex);

    for (int i = 0; i < threads; i++)
        pthread_join(tids[i], NULL);

    free(tids);
    return 0;
}

// ------------------------------
// Main
// ------------------------------
int main(int argc, char *argv[]) {
    static char user_buf[256], pass_buf[256], host_buf[512], name_buf[256];

    int argi = 1;

    // CONFIG MODE FIRST
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

    // STRICT ARGUMENT MODE
    if (argi == 1) {
        if (argc < 7) {
            printf("Usage:\n");
            printf("  %s -c <configfile>\n", argv[0]);
            printf("  %s 'db_usr=\"user\"' 'db_passwd=\"pw\"' 'db_hst=\"url\"' 'db_name=\"dbname\"' <file>\n", argv[0]);
            printf("  %s 'db_usr=\"user\"' 'db_passwd=\"pw\"' 'db_hst=\"url\"' 'db_name=\"dbname\"' -p N -r <folder>\n", argv[0]);
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

    if (curl_global_init(CURL_GLOBAL_DEFAULT) != 0) {
        fprintf(stderr, "curl_global_init failed\n");
        return 1;
    }

    int ret;

    // SINGLE FILE MODE
    if (argc - argi == 1) {
        ret = upload_attachment(argv[argi]);
        curl_global_cleanup();
        return ret;
    }

    // PARALLEL RECURSIVE MODE
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
