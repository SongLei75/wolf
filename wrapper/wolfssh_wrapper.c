/* wolfssh_wrapper.c — Python C extension for wolfssh X.509 authentication.
 *
 * Provides wolfssh_wrapper.X509Identity for paramiko integration.
 * No C API exported — pure Python C extension only.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssl/wolfcrypt/ecc.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/random.h>

#ifdef WOLFSSH_CERTS
    #include <wolfssl/wolfcrypt/asn.h>
    #include <wolfssl/wolfcrypt/asn_public.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define PY_SSIZE_T_CLEAN
#include <Python.h>

/* ════════════════════════════════════════════════════════════════════════════
 * Helpers
 * ════════════════════════════════════════════════════════════════════════════ */

static int load_file(const char* filename, byte** out, word32* outSz)
{
    FILE* f = fopen(filename, "rb");
    if (!f) return -1;
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    if (sz <= 0) { fclose(f); return -1; }
    byte* buf = (byte*)malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return -1; }
    if ((long)fread(buf, 1, (size_t)sz, f) != sz) {
        free(buf); fclose(f); return -1;
    }
    buf[sz] = '\0';
    fclose(f);
    *out = buf; *outSz = (word32)sz;
    return 0;
}

/* ── X.509 key type strings (static, no allocation) ── */

#ifdef WOLFSSH_CERTS
static const byte x509_p256[] = "x509v3-ecdsa-sha2-nistp256";
static const byte x509_p384[] = "x509v3-ecdsa-sha2-nistp384";
static const byte x509_p521[] = "x509v3-ecdsa-sha2-nistp521";

static const byte* resolve_x509_type(const byte* priv_key_type, word32* outSz)
{
    if (priv_key_type) {
        const char* pt = (const char*)priv_key_type;
        if (strstr(pt, "nistp521")) { *outSz = sizeof(x509_p521)-1; return x509_p521; }
        if (strstr(pt, "nistp384")) { *outSz = sizeof(x509_p384)-1; return x509_p384; }
    }
    *outSz = sizeof(x509_p256)-1; return x509_p256;
}
#endif

/* ── SSH wire format ── */

static void write_u32be(byte* dst, word32 val)
{
    dst[0] = (byte)((val >> 24) & 0xFF);
    dst[1] = (byte)((val >> 16) & 0xFF);
    dst[2] = (byte)((val >>  8) & 0xFF);
    dst[3] = (byte)((val      ) & 0xFF);
}

static word32 mpint_encode(byte* dst, const byte* val, word32 len)
{
    while (len > 1 && val[0] == 0x00) { val++; len--; }
    if (len == 0) { write_u32be(dst, 1); dst[4] = 0x00; return 5; }
    if (val[0] & 0x80) {
        write_u32be(dst, len + 1); dst[4] = 0x00;
        memcpy(dst + 5, val, len); return 4 + 1 + len;
    }
    write_u32be(dst, len); memcpy(dst + 4, val, len); return 4 + len;
}

static int parse_der_sig(const byte* der, word32 derSz,
    const byte** r_out, word32* r_len, const byte** s_out, word32* s_len)
{
    word32 i = 0;
    if (derSz < 6 || der[i] != 0x30) return -1;
    i++;
    i += (der[i] & 0x80) ? (der[i] & 0x7F) + 1 : 1;
    if (i >= derSz || der[i] != 0x02) return -1;
    i++; *r_len = der[i]; i++;
    if (i + *r_len > derSz) return -1;
    *r_out = der + i; i += *r_len;
    if (i >= derSz || der[i] != 0x02) return -1;
    i++; *s_len = der[i]; i++;
    if (i + *s_len > derSz) return -1;
    *s_out = der + i;
    return 0;
}

static int get_ecc_hash_type(const char* algorithm)
{
    if (!algorithm) return WC_HASH_TYPE_SHA256;
    if (strstr(algorithm, "nistp521")) return WC_HASH_TYPE_SHA512;
    if (strstr(algorithm, "nistp384")) return WC_HASH_TYPE_SHA384;
    return WC_HASH_TYPE_SHA256;
}

/* ════════════════════════════════════════════════════════════════════════════
 * X509Identity Python type
 * ════════════════════════════════════════════════════════════════════════════ */

typedef struct {
    PyObject_HEAD
    byte*   priv_key;       /* DER-encoded private key */
    word32  priv_key_sz;
    byte*   pub_key;        /* cert DER (or raw) */
    word32  pub_key_sz;
    const byte* key_type;   /* "x509v3-ecdsa-sha2-nistp256" (static) */
    word32  key_type_sz;
    PyObject* py_key_type;  /* cached str */
    PyObject* py_ssh_blob;  /* cached bytes */
} X509Identity;

static void X509_dealloc(X509Identity* self)
{
    WFREE(self->priv_key, NULL, DYNTYPE_FILE);
    free(self->pub_key);
    Py_XDECREF(self->py_key_type);
    Py_XDECREF(self->py_ssh_blob);
    Py_TYPE(self)->tp_free((PyObject*)self);
}

static PyObject* X509_get_key_type(X509Identity* self, PyObject* a)
{
    (void)a;
    Py_INCREF(self->py_key_type);
    return self->py_key_type;
}

static PyObject* X509_get_ssh_blob(X509Identity* self, PyObject* a)
{
    (void)a;
    Py_INCREF(self->py_ssh_blob);
    return self->py_ssh_blob;
}

static PyObject* X509_sign(X509Identity* self, PyObject* args)
{
    Py_buffer data_buf;
    const char* algorithm;
    if (!PyArg_ParseTuple(args, "y*s", &data_buf, &algorithm)) return NULL;

    /* Strip "x509v3-" prefix from algorithm for ECC signing */
    const char* ecdsa_algo = algorithm;
    if (strncmp(ecdsa_algo, "x509v3-", 7) == 0) ecdsa_algo += 7;
    word32 algoLen = (word32)strlen(ecdsa_algo);

    /* Hash */
    int hashType = get_ecc_hash_type(ecdsa_algo);
    int digestSz = wc_HashGetDigestSize((enum wc_HashType)hashType);
    if (digestSz <= 0) {
        PyBuffer_Release(&data_buf);
        return PyErr_Format(PyExc_RuntimeError, "unsupported hash: %s", ecdsa_algo);
    }
    byte digest[WC_MAX_DIGEST_SIZE];
    if (wc_Hash((enum wc_HashType)hashType,
            (const byte*)data_buf.buf, (word32)data_buf.len,
            digest, sizeof(digest)) != 0) {
        PyBuffer_Release(&data_buf);
        PyErr_SetString(PyExc_RuntimeError, "hash failed");
        return NULL;
    }

    /* ECC sign → DER signature */
    WC_RNG rng;
    ecc_key ecc;
    word32 idx = 0;
    if (wc_InitRng(&rng) != 0) {
        PyBuffer_Release(&data_buf);
        PyErr_SetString(PyExc_RuntimeError, "RNG init failed");
        return NULL;
    }
    if (wc_ecc_init(&ecc) != 0) {
        wc_FreeRng(&rng);
        PyBuffer_Release(&data_buf);
        PyErr_SetString(PyExc_RuntimeError, "ECC init failed");
        return NULL;
    }
    byte derSig[256];
    word32 derSigSz = sizeof(derSig);
    int signRet = wc_EccPrivateKeyDecode(self->priv_key, &idx, &ecc, self->priv_key_sz);
    if (signRet == 0)
        signRet = wc_ecc_sign_hash(digest, (word32)digestSz, derSig, &derSigSz, &rng, &ecc);
    wc_ecc_free(&ecc);
    wc_FreeRng(&rng);
    if (signRet != 0) {
        PyBuffer_Release(&data_buf);
        PyErr_SetString(PyExc_RuntimeError, "ECC sign failed");
        return NULL;
    }

    /* Parse DER sig → r, s */
    const byte *r_raw, *s_raw;
    word32 r_len, s_len;
    if (parse_der_sig(derSig, derSigSz, &r_raw, &r_len, &s_raw, &s_len) != 0) {
        PyBuffer_Release(&data_buf);
        PyErr_SetString(PyExc_RuntimeError, "DER sig parse failed");
        return NULL;
    }
    while (r_len > 1 && r_raw[0] == 0x00) { r_raw++; r_len--; }
    while (s_len > 1 && s_raw[0] == 0x00) { s_raw++; s_len--; }

    /* Encode r, s as SSH mpints */
    byte mpint_buf[512];
    word32 mpint_len  = mpint_encode(mpint_buf, r_raw, r_len);
    mpint_len        += mpint_encode(mpint_buf + mpint_len, s_raw, s_len);

    /* Build SSH wire signature: string(algo) + string(r||s) */
    word32 wire_sz = 4 + algoLen + 4 + mpint_len;
    byte* wire = (byte*)PyMem_Malloc(wire_sz);
    if (!wire) { PyBuffer_Release(&data_buf); return PyErr_NoMemory(); }

    word32 off = 0;
    write_u32be(wire+off, algoLen);                off += 4;
    memcpy(wire+off, ecdsa_algo, algoLen);          off += algoLen;
    write_u32be(wire+off, mpint_len);               off += 4;
    memcpy(wire+off, mpint_buf, mpint_len);         off += mpint_len;

    PyBuffer_Release(&data_buf);
    PyObject* result = PyBytes_FromStringAndSize((char*)wire, wire_sz);
    PyMem_Free(wire);
    return result;
}

static PyMethodDef X509_methods[] = {
    {"get_key_type", (PyCFunction)X509_get_key_type, METH_NOARGS, NULL},
    {"get_ssh_blob", (PyCFunction)X509_get_ssh_blob, METH_NOARGS, NULL},
    {"sign",         (PyCFunction)X509_sign,         METH_VARARGS, NULL},
    {NULL, NULL, 0, NULL}
};

static int X509_init(X509Identity* self, PyObject* args, PyObject* kwargs)
{
    static const char* kwlist[] = {"keyfile", "certfile", "cafile", NULL};
    const char *keyfile = NULL, *certfile = NULL, *cafile = NULL;

    if (!PyArg_ParseTupleAndKeywords(args, kwargs, "s|zz",
            (char**)kwlist, &keyfile, &certfile, &cafile))
        return -1;

    (void)cafile; /* reserved for future use */

    /* Free previous state (for re-init) */
    WFREE(self->priv_key, NULL, DYNTYPE_FILE); self->priv_key = NULL;
    free(self->pub_key);  self->pub_key = NULL;
    Py_CLEAR(self->py_key_type);
    Py_CLEAR(self->py_ssh_blob);

    /* Load private key via wolfssh */
    byte isPrivate = 0;
    const byte* priv_type = NULL;
    word32 priv_type_sz = 0;
    int ret = wolfSSH_ReadKey_file(keyfile,
            &self->priv_key, &self->priv_key_sz,
            &priv_type, &priv_type_sz, &isPrivate, NULL);
    if (ret != 0) {
        PyErr_Format(PyExc_RuntimeError, "failed to load key: %s", keyfile);
        return -1;
    }

    /* Resolve x509 key type */
    self->key_type = resolve_x509_type(priv_type, &self->key_type_sz);
    self->py_key_type = PyUnicode_FromStringAndSize(
        (const char*)self->key_type, self->key_type_sz);
    if (self->py_key_type == NULL) {
        /* CPython already set the exception */
        return -1;
    }

    /* Load certificate → DER */
#ifdef WOLFSSH_CERTS
    {
        const char* certSrc = certfile ? certfile : keyfile;
        byte* raw = NULL;
        word32 rawSz = 0;
        if (load_file(certSrc, &raw, &rawSz) != 0) {
            PyErr_Format(PyExc_RuntimeError, "failed to read cert: %s", certSrc);
            return -1;
        }
        const char* pemHdr = "-----BEGIN CERTIFICATE-----";
        if (rawSz > 27 && strstr((char*)raw, pemHdr)) {
            /* PEM → DER: concatenate all cert DER blocks */
            byte* combined = NULL;
            word32 combinedSz = 0;
            const char* p = (const char*)raw;
            const char* end = (const char*)raw + rawSz;
            while (p < end) {
                const char* begin = strstr(p, pemHdr);
                if (!begin) break;
                const char* endM = strstr(begin, "-----END CERTIFICATE-----");
                if (!endM) break;
                endM += strlen("-----END CERTIFICATE-----");
                while (endM < end && (*endM == '\r' || *endM == '\n')) endM++;
                int pemBlockSz = (int)(endM - begin);
                byte derBuf[4096];
                int derSz = wc_CertPemToDer(
                    (const unsigned char*)begin, pemBlockSz,
                    derBuf, (int)sizeof(derBuf), CERT_TYPE);
                if (derSz > 0) {
                    byte* tmp = (byte*)realloc(combined, combinedSz + derSz);
                    if (!tmp) { free(combined); free(raw); PyErr_NoMemory(); return -1; }
                    combined = tmp;
                    memcpy(combined + combinedSz, derBuf, derSz);
                    combinedSz += derSz;
                }
                p = endM;
            }
            free(raw);
            if (!combined || combinedSz == 0) {
                PyErr_SetString(PyExc_RuntimeError, "no valid certs in PEM");
                return -1;
            }
            self->pub_key = combined;
            self->pub_key_sz = combinedSz;
        } else {
            self->pub_key = raw;
            self->pub_key_sz = rawSz;
        }
    }
#endif

    /* Build SSH blob: string(algo) | uint32(1) | string(cert_DER) | uint32(0) */
    word32 blob_sz = 4 + self->key_type_sz + 4 + 4 + self->pub_key_sz + 4;
    byte* blob = (byte*)PyMem_Malloc(blob_sz);
    if (!blob) { PyErr_NoMemory(); return -1; }

    word32 off = 0;
    write_u32be(blob+off, self->key_type_sz);          off += 4;
    memcpy(blob+off, self->key_type, self->key_type_sz); off += self->key_type_sz;
    write_u32be(blob+off, 1);                           off += 4;
    write_u32be(blob+off, self->pub_key_sz);           off += 4;
    memcpy(blob+off, self->pub_key, self->pub_key_sz); off += self->pub_key_sz;
    write_u32be(blob+off, 0);                           off += 4;

    self->py_ssh_blob = PyBytes_FromStringAndSize((char*)blob, blob_sz);
    PyMem_Free(blob);
    if (self->py_ssh_blob == NULL) {
        Py_CLEAR(self->py_key_type);
        return -1;
    }
    return 0;
}

static PyTypeObject X509IdentityType = {
    PyVarObject_HEAD_INIT(NULL, 0)
    .tp_name      = "wolfssh_wrapper.X509Identity",
    .tp_basicsize = sizeof(X509Identity),
    .tp_dealloc   = (destructor)X509_dealloc,
    .tp_flags     = Py_TPFLAGS_DEFAULT,
    .tp_doc       = "X.509 identity for paramiko.",
    .tp_methods   = X509_methods,
    .tp_new       = PyType_GenericNew,
    .tp_init      = (initproc)X509_init,
};

/* ════════════════════════════════════════════════════════════════════════════
 * Module
 * ════════════════════════════════════════════════════════════════════════════ */

static struct PyModuleDef module_def = {
    PyModuleDef_HEAD_INIT, "wolfssh_wrapper",
    "wolfssh X.509 auth extension for paramiko", -1, NULL,
};

PyMODINIT_FUNC PyInit_wolfssh_wrapper(void)
{
    if (PyType_Ready(&X509IdentityType) < 0) return NULL;
    PyObject* m = PyModule_Create(&module_def);
    if (!m) return NULL;
    Py_INCREF(&X509IdentityType);
    if (PyModule_AddObject(m, "X509Identity", (PyObject*)&X509IdentityType) < 0) {
        Py_DECREF(&X509IdentityType); Py_DECREF(m); return NULL;
    }
    return m;
}
