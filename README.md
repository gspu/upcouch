📦 upcouch — Parallel CouchDB File Uploader for FreeBSD

**upcouch** is a lightweight C program that uploads files to a CouchDB database.  
It supports:

- Parallel uploads (`-p N`)
- Recursive directory traversal (`-r DIR`)
- Binary‑safe Base64 attachments
- Strict argument order
- Optional config‑file mode (`-c file.conf`)
- Max file size: 4 GiB
- Max threads: 64

Designed and tested on **FreeBSD** using **Clang**, **libcurl**, and **FTS**.

## 🛠️ Requirements (FreeBSD)

Install the required package:

```sh
pkg install curl
```

FreeBSD already includes:

- `clang` (compiler)
- `libpthread` (threads)
- `fts` (file tree traversal)

---

## 🔧 How to Compile on FreeBSD

Compile using:

```sh
cc upcouch.c -pthread -I/usr/local/include -L/usr/local/lib -lcurl -o upcouch
```
or

```sh
make
```

Explanation:

- `-pthread` → enables POSIX threads  
- `-I/usr/local/include` → curl headers  
- `-L/usr/local/lib` → curl libraries  
- `-lcurl` → link against libcurl  
- `-o upcouch` → output binary  

---

## 🚀 What upcouch Does

upcouch uploads files to a CouchDB database as **Base64‑encoded attachments**.

For each file:

- Reads file as binary  
- Base64‑encodes it  
- Wraps it in a JSON document  
- Sends it to CouchDB via HTTP POST  
- Uses HTTP Basic Auth  
- Creates one document per file  

In recursive mode:

- Walks the directory tree using `fts(3)`
- Pushes each file into a thread‑safe queue
- Uploads files in parallel using worker threads

---

## 📘 Usage

Strict argument order:

```
upcouch 'db_usr="USER"' 'db_passwd="PASS"' 'db_hst="HOSTURL"' 'db_name="DBNAME"' <file>

upcouch 'db_usr="USER"' 'db_passwd="PASS"' 'db_hst="HOSTURL"' 'db_name="DBNAME"' -p N -r <folder>
```

---

## 📄 Examples

### 1. Upload a single file

```sh
./upcouch 'db_usr="admin"' \
          'db_passwd="changeme123"' \
          'db_hst="http://127.0.0.1:5984"' \
          'db_name="test"' \
          myfile.bin
```

---

### 2. Upload your home directory with 4 threads

```sh
./upcouch 'db_usr="admin"' \
          'db_passwd="changeme123"' \
          'db_hst="http://127.0.0.1:5984"' \
          'db_name="backup"' \
          -p 4 -r /home/youruser/
```

### Use deterministic document IDs based on the filename with added sha256

```sh
./upcouch -c example.conf -n myfile.bin -> myfile_bin_sha256fsdicerti43456erge
```
 -n Use deterministic document IDs based on the filename.
    This causes uploads to use PUT instead of POST.
    Re-uploading the same filename overwrites the same document.

### Using a config file

upcouch can load all database parameters from a config file:

```sh
./upcouch -c example.conf -p 4 -r /home/youruser/
```

Example config file:

    db_usr="admin"
    db_passwd="passwd"
    db_hst="http://127.0.0.1:5984"
    db_name="mydb"

---

## ⚠️ Notes

- upcouch **does not** create the database automatically — ensure it exists in CouchDB.
- Each file becomes a **separate document**.
- Filenames are used as attachment names.
- Credentials are **not stored** in the binary or source — only passed at runtime.

---

## 🧩 Troubleshooting

### “Invalid argument”
Use single quotes around each argument:

```
'db_usr="admin"'
```

### “curl error: Unsupported protocol”
Usually caused by:

- malformed `db_hst="..."`  
- missing quotes  
- shell stripping quotes  

Always wrap arguments in single quotes.
