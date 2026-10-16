"""
Curated catalog of security-relevant native symbols.

Each category maps to a set of symbol-name patterns. Patterns may be:
- Exact strings
- Prefix patterns (ending with *)
- Suffix patterns (starting with *)

Symbols not matching any pattern are aggregated in `total_count` but
not listed individually. The categories below are fixed at v1.2.2;
adding a category requires updating models.py.
"""

# Each value is a list of patterns. "*" is a wildcard at start or end.
_CATEGORIES: dict[str, list[str]] = {
    "crypto": [
        # OpenSSL / BoringSSL primitive APIs
        "AES_*", "DES_*", "BF_*", "RC4_*", "RC2_*",
        "EVP_*", "HMAC_*",
        "MD5_*", "MD4_*", "SHA_*", "SHA1_*", "SHA256_*", "SHA512_*",
        "RSA_*", "DSA_*", "EC_*", "ECDH_*", "ECDSA_*", "DH_*",
        "BN_*", "BIO_*", "CRYPTO_*", "RAND_*",
        "PKCS5_*", "PKCS7_*", "PKCS12_*",
        "PEM_*", "ASN1_*",
        # mbedtls
        "mbedtls_aes_*", "mbedtls_md5_*", "mbedtls_sha*",
        "mbedtls_rsa_*", "mbedtls_ecdh_*", "mbedtls_ecdsa_*",
        "mbedtls_cipher_*", "mbedtls_md_*",
        # Tink
        "tink_*",
        # Common primitive names
        "Curve25519_*", "ed25519_*", "x25519_*",
        "chacha20_*", "poly1305_*",
        "scrypt_*", "argon2_*", "pbkdf2_*",
    ],

    "tls": [
        "SSL_*", "TLS_*", "X509_*",
        "DTLS_*",
        "mbedtls_ssl_*", "mbedtls_x509_*",
        "wolfSSL_*", "wolfTLS_*",
    ],

    "network": [
        "socket", "connect", "bind", "listen", "accept",
        "send", "sendto", "sendmsg",
        "recv", "recvfrom", "recvmsg",
        "getaddrinfo", "freeaddrinfo",
        "gethostbyname", "gethostbyaddr",
        "inet_addr", "inet_aton", "inet_pton", "inet_ntop",
        "shutdown", "setsockopt", "getsockopt",
        "if_nametoindex",
        "curl_easy_*", "curl_multi_*", "curl_global_*",
    ],

    "process": [
        "fork", "vfork", "clone",
        "execve", "execvp", "execl", "execlp",
        "kill", "killpg", "raise",
        "getpid", "getppid", "gettid",
        "setuid", "setgid", "setreuid", "setregid",
        "wait", "waitpid", "waitid",
        "system", "popen",
    ],

    "file_io": [
        "open", "openat", "creat",
        "read", "pread", "readv",
        "write", "pwrite", "writev",
        "close", "fcntl",
        "fopen", "fclose", "fread", "fwrite",
        "stat", "fstat", "lstat", "fstatat",
        "access", "faccessat",
        "unlink", "unlinkat", "remove", "rename",
        "mkdir", "mkdirat", "rmdir",
        "chmod", "fchmod", "fchmodat",
        "chown", "fchown", "lchown", "fchownat",
        "readlink", "readlinkat", "symlink",
        "mmap", "munmap", "mprotect",
    ],

    "dynamic": [
        "dlopen", "dlsym", "dlclose", "dlerror",
        "dl_iterate_phdr", "dlvsym",
        "android_dlopen_ext",
    ],

    "debug_detection": [
        "ptrace",
        "prctl",
        "getauxval",
        "__system_property_get", "__system_property_find",
        "personality",
        "syscall",
    ],

    # Symbol-only category — string-based detection for root_detection
    # is handled by suspicious_patterns at the builder level rather than
    # here, since it requires combining imports with .rodata content.
    "root_detection": [
        # No symbol-only patterns; populated by the builder when
        # file_io imports are combined with root-related .rodata strings.
    ],

    "jni": [
        "JNI_OnLoad", "JNI_OnUnload",
        "RegisterNatives",
        "JNI_GetCreatedJavaVMs", "JNI_CreateJavaVM",
        "GetEnv",
        # JNIEnv functions are reached as members of *env, not symbols,
        # so they don't appear in dynamic imports. We catch JNI_OnLoad
        # and RegisterNatives as the meaningful ones.
    ],
}


def categorize(symbol: str) -> str | None:
    """
    Return the category a symbol belongs to, or None if uncategorized.

    Matches in order: exact, prefix, suffix. The first match wins; a
    symbol cannot belong to multiple categories.
    """
    for category, patterns in _CATEGORIES.items():
        for pattern in patterns:
            if _matches(symbol, pattern):
                return category
    return None


def _matches(symbol: str, pattern: str) -> bool:
    """Apply a single pattern. * is wildcard at start or end only."""
    if pattern == symbol:
        return True
    if pattern.endswith("*") and symbol.startswith(pattern[:-1]):
        return True
    if pattern.startswith("*") and symbol.endswith(pattern[1:]):
        return True
    return False


def categories() -> list[str]:
    """Return the fixed list of category names in declaration order."""
    return list(_CATEGORIES.keys())