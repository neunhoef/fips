// Minimal worked example: AES-256-GCM "encryption at rest" using the
// OpenSSL 3.x FIPS provider (see https://docs.openssl.org/master/man7/fips_module/).
//
// The key idea from that manual page that this program demonstrates:
//   1. The FIPS provider must be loaded explicitly (it is never the default).
//   2. Algorithms must be *fetched* with the property query "fips=yes" so
//      that OpenSSL refuses to silently fall back to a non-validated
//      implementation from the "default" provider.
//   3. Whether the FIPS provider is actually active is a *runtime*
//      property of the OpenSSL configuration (openssl.cnf / OPENSSL_CONF),
//      not something baked into the binary at compile time.
//
// File format written to disk (all sizes in bytes):
//   [12: GCM nonce] [N: ciphertext] [16: GCM authentication tag]
//
// Usage:
//   fips_file_crypt                         run a self-contained demo in ./demo/
//   fips_file_crypt genkey    <keyfile>
//   fips_file_crypt encrypt <keyfile> <in> <out>
//   fips_file_crypt decrypt <keyfile> <in> <out>

#include <openssl/core_names.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/params.h>
#include <openssl/provider.h>
#include <openssl/rand.h>

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

namespace {

constexpr std::size_t kKeyLen = 32;   // AES-256
constexpr std::size_t kIvLen = 12;    // recommended GCM nonce length
constexpr std::size_t kTagLen = 16;   // full-size GCM authentication tag

// A fixed "additional authenticated data" context. AAD is authenticated but
// not encrypted; it is a convenient place to bind ciphertext to context
// (e.g. a key id, a schema version) without hiding it. Both sides must agree
// on it out of band, so we don't store it in the file.
constexpr std::string_view kAad = "fips-file-crypt-v1";

[[noreturn]] void throw_openssl_error(const std::string& what) {
    unsigned long code = ERR_get_error();
    char buf[256];
    ERR_error_string_n(code, buf, sizeof(buf));
    throw std::runtime_error(what + ": " + buf);
}

// RAII wrapper so early throws can't leak the cipher context.
struct CipherCtx {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    CipherCtx() {
        if (!ctx) throw_openssl_error("EVP_CIPHER_CTX_new failed");
    }
    ~CipherCtx() { EVP_CIPHER_CTX_free(ctx); }
    CipherCtx(const CipherCtx&) = delete;
    CipherCtx& operator=(const CipherCtx&) = delete;
    operator EVP_CIPHER_CTX*() const { return ctx; }
};

// Loads the FIPS provider and reports whether it is really active.
//
// The provider is only loadable if:
//   - a FIPS module (fips.so) is installed where OpenSSL's module
//     directory (or OPENSSL_MODULES) points, AND
//   - `openssl fipsinstall` has been run against it and the resulting
//     fipsmodule.cnf is reachable via the active OpenSSL config file
//     (OPENSSL_CONF), so the provider's self-tests / integrity check pass.
//
// See scripts/setup_fips_module.sh in this repo for how that is done.
bool load_fips_provider() {
    OSSL_PROVIDER* fips = OSSL_PROVIDER_load(nullptr, "fips");
    if (!fips) {
        // Not fatal for the demo: fall back to the default provider so the
        // example still runs, but make noise about it. Note that merely
        // *attempting* OSSL_PROVIDER_load() above (even on failure) turns
        // off OpenSSL's automatic implicit loading of the default
        // provider, so it must now be requested explicitly.
        ERR_clear_error();
        if (!OSSL_PROVIDER_load(nullptr, "default")) throw_openssl_error("OSSL_PROVIDER_load(default) failed");
        return false;
    }
    // The "base" provider supplies non-cryptographic helpers (encoders,
    // etc.) that some FIPS-provider operations rely on being available.
    OSSL_PROVIDER_load(nullptr, "base");
    return true;
}

// Fetches AES-256-GCM, preferring the FIPS-validated implementation when
// available. Throws if FIPS was requested but only a non-FIPS
// implementation could be found -- silently downgrading defeats the point.
EVP_CIPHER* fetch_aes_256_gcm(bool require_fips) {
    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, "AES-256-GCM",
                                           require_fips ? "fips=yes" : nullptr);
    if (!cipher) throw_openssl_error("EVP_CIPHER_fetch(AES-256-GCM) failed");
    return cipher;
}

void write_file(const std::filesystem::path& path, std::span<const std::uint8_t> data) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("cannot open for writing: " + path.string());
    out.write(reinterpret_cast<const char*>(data.data()),
              static_cast<std::streamsize>(data.size()));
}

std::vector<std::uint8_t> read_file(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary | std::ios::ate);
    if (!in) throw std::runtime_error("cannot open for reading: " + path.string());
    auto size = in.tellg();
    in.seekg(0);
    std::vector<std::uint8_t> data(static_cast<std::size_t>(size));
    in.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

void generate_key_file(const std::filesystem::path& keyfile, bool require_fips) {
    // Once the FIPS provider is active, RAND_bytes() draws from the
    // FIPS-approved CTR-DRBG the provider installs as the default RNG;
    // there is nothing else to opt in to here.
    std::vector<std::uint8_t> key(kKeyLen);
    if (RAND_bytes(key.data(), static_cast<int>(key.size())) != 1) {
        throw_openssl_error("RAND_bytes failed");
    }
    write_file(keyfile, key);
    std::filesystem::permissions(keyfile, std::filesystem::perms::owner_read |
                                               std::filesystem::perms::owner_write);
    std::cerr << "Wrote " << key.size() << "-byte key to " << keyfile
              << " (demo only: a real deployment must not store the key next to the "
                 "ciphertext -- use a KMS/HSM or a wrapped-key scheme instead)\n";
    (void)require_fips;
}

std::vector<std::uint8_t> load_key(const std::filesystem::path& keyfile) {
    auto key = read_file(keyfile);
    if (key.size() != kKeyLen) {
        throw std::runtime_error("key file has wrong size (expected " +
                                  std::to_string(kKeyLen) + " bytes)");
    }
    return key;
}

// AEAD encrypt: returns [iv][ciphertext][tag].
std::vector<std::uint8_t> aead_encrypt(const EVP_CIPHER* cipher,
                                        std::span<const std::uint8_t> key,
                                        std::span<const std::uint8_t> plaintext) {
    std::vector<std::uint8_t> iv(kIvLen);
    if (RAND_bytes(iv.data(), static_cast<int>(iv.size())) != 1) {
        throw_openssl_error("RAND_bytes (iv) failed");
    }

    CipherCtx ctx;
    if (EVP_EncryptInit_ex2(ctx, cipher, key.data(), iv.data(), nullptr) != 1) {
        throw_openssl_error("EVP_EncryptInit_ex2 failed");
    }

    int len = 0;
    if (EVP_EncryptUpdate(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(kAad.data()),
                           static_cast<int>(kAad.size())) != 1) {
        throw_openssl_error("EVP_EncryptUpdate (AAD) failed");
    }

    std::vector<std::uint8_t> ciphertext(plaintext.size());
    if (EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(),
                           static_cast<int>(plaintext.size())) != 1) {
        throw_openssl_error("EVP_EncryptUpdate (plaintext) failed");
    }
    int total = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext.data() + total, &len) != 1) {
        throw_openssl_error("EVP_EncryptFinal_ex failed");
    }
    total += len;
    ciphertext.resize(static_cast<std::size_t>(total));

    std::vector<std::uint8_t> tag(kTagLen);
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG, tag.data(), tag.size()),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_CIPHER_CTX_get_params(ctx, params) != 1) {
        throw_openssl_error("EVP_CIPHER_CTX_get_params (get tag) failed");
    }

    std::vector<std::uint8_t> out;
    out.reserve(iv.size() + ciphertext.size() + tag.size());
    out.insert(out.end(), iv.begin(), iv.end());
    out.insert(out.end(), ciphertext.begin(), ciphertext.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

std::vector<std::uint8_t> aead_decrypt(const EVP_CIPHER* cipher,
                                        std::span<const std::uint8_t> key,
                                        std::span<const std::uint8_t> blob) {
    if (blob.size() < kIvLen + kTagLen) {
        throw std::runtime_error("ciphertext file too short / corrupt");
    }
    auto iv = blob.subspan(0, kIvLen);
    auto ciphertext = blob.subspan(kIvLen, blob.size() - kIvLen - kTagLen);
    auto tag = blob.subspan(blob.size() - kTagLen, kTagLen);

    CipherCtx ctx;
    if (EVP_DecryptInit_ex2(ctx, cipher, key.data(), iv.data(), nullptr) != 1) {
        throw_openssl_error("EVP_DecryptInit_ex2 failed");
    }

    int len = 0;
    if (EVP_DecryptUpdate(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(kAad.data()),
                           static_cast<int>(kAad.size())) != 1) {
        throw_openssl_error("EVP_DecryptUpdate (AAD) failed");
    }

    std::vector<std::uint8_t> plaintext(ciphertext.size());
    if (EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(),
                           static_cast<int>(ciphertext.size())) != 1) {
        throw_openssl_error("EVP_DecryptUpdate (ciphertext) failed");
    }
    int total = len;

    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_octet_string(OSSL_CIPHER_PARAM_AEAD_TAG,
                                           const_cast<std::uint8_t*>(tag.data()), tag.size()),
        OSSL_PARAM_construct_end(),
    };
    if (EVP_CIPHER_CTX_set_params(ctx, params) != 1) {
        throw_openssl_error("EVP_CIPHER_CTX_set_params (set tag) failed");
    }

    // EVP_DecryptFinal_ex returning 0 here means the GCM tag did not
    // verify: the ciphertext or AAD was tampered with (or corrupted), and
    // the plaintext buffer must be discarded, not trusted.
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &len) != 1) {
        throw_openssl_error("tag verification failed: ciphertext is corrupt or was tampered with");
    }
    total += len;
    plaintext.resize(static_cast<std::size_t>(total));
    return plaintext;
}

void encrypt_file(bool require_fips, const std::filesystem::path& keyfile,
                   const std::filesystem::path& infile, const std::filesystem::path& outfile) {
    EVP_CIPHER* cipher = fetch_aes_256_gcm(require_fips);
    std::cerr << "Using AES-256-GCM from provider '"
              << OSSL_PROVIDER_get0_name(EVP_CIPHER_get0_provider(cipher)) << "'\n";
    auto key = load_key(keyfile);
    auto plaintext = read_file(infile);
    auto blob = aead_encrypt(cipher, key, plaintext);
    write_file(outfile, blob);
    EVP_CIPHER_free(cipher);
    std::cerr << "Encrypted " << plaintext.size() << " bytes -> " << outfile << " (" << blob.size()
              << " bytes)\n";
}

void decrypt_file(bool require_fips, const std::filesystem::path& keyfile,
                   const std::filesystem::path& infile, const std::filesystem::path& outfile) {
    EVP_CIPHER* cipher = fetch_aes_256_gcm(require_fips);
    std::cerr << "Using AES-256-GCM from provider '"
              << OSSL_PROVIDER_get0_name(EVP_CIPHER_get0_provider(cipher)) << "'\n";
    auto key = load_key(keyfile);
    auto blob = read_file(infile);
    auto plaintext = aead_decrypt(cipher, key, blob);
    write_file(outfile, plaintext);
    EVP_CIPHER_free(cipher);
    std::cerr << "Decrypted " << blob.size() << " bytes -> " << outfile << " (" << plaintext.size()
              << " bytes)\n";
}

int run_demo(bool require_fips) {
    namespace fs = std::filesystem;
    fs::path dir = "demo";
    fs::create_directories(dir);

    fs::path keyfile = dir / "master.key";
    fs::path plainfile = dir / "plaintext.txt";
    fs::path encfile = dir / "plaintext.txt.enc";
    fs::path roundtripfile = dir / "plaintext.roundtrip.txt";

    write_file(plainfile, std::vector<std::uint8_t>{'H', 'e', 'l', 'l', 'o', ',', ' ', 'F', 'I',
                                                      'P', 'S', '!', '\n'});
    generate_key_file(keyfile, require_fips);
    encrypt_file(require_fips, keyfile, plainfile, encfile);
    decrypt_file(require_fips, keyfile, encfile, roundtripfile);

    auto original = read_file(plainfile);
    auto roundtrip = read_file(roundtripfile);
    if (original != roundtrip) {
        std::cerr << "MISMATCH: round-tripped plaintext differs from original!\n";
        return 1;
    }
    std::cerr << "Round trip OK: decrypted content matches the original.\n";
    return 0;
}

void print_usage(const char* argv0) {
    std::cerr << "Usage:\n"
              << "  " << argv0 << "                              run a self-contained demo\n"
              << "  " << argv0 << " genkey   <keyfile>\n"
              << "  " << argv0 << " encrypt  <keyfile> <infile> <outfile>\n"
              << "  " << argv0 << " decrypt  <keyfile> <infile> <outfile>\n";
}

}  // namespace

int main(int argc, char** argv) {
    bool fips_active = load_fips_provider();
    if (fips_active) {
        std::cerr << "FIPS provider loaded and active.\n";
    } else {
        std::cerr << "WARNING: FIPS provider could not be loaded -- falling back to the "
                     "default (non-FIPS-validated) provider. See scripts/setup_fips_module.sh.\n";
    }

    try {
        std::vector<std::string> args(argv + 1, argv + argc);

        if (args.empty()) {
            return run_demo(fips_active);
        }
        if (args[0] == "genkey" && args.size() == 2) {
            generate_key_file(args[1], fips_active);
            return 0;
        }
        if (args[0] == "encrypt" && args.size() == 4) {
            encrypt_file(fips_active, args[1], args[2], args[3]);
            return 0;
        }
        if (args[0] == "decrypt" && args.size() == 4) {
            decrypt_file(fips_active, args[1], args[2], args[3]);
            return 0;
        }
        print_usage(argv[0]);
        return 2;
    } catch (const std::exception& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}
