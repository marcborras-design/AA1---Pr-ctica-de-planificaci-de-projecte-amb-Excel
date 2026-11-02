#ifndef VAULT_CORE_HPP
#ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0A00
#endif
#define VAULT_CORE_HPP

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#include <climits>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

constexpr size_t SALT_LEN = 16;
constexpr size_t IV_LEN = 12;
constexpr size_t KEY_LEN = 32;
constexpr size_t TAG_LEN = 16;
constexpr size_t HASH_LEN = 32;

constexpr uint32_t MEMCOST = 65536;
constexpr uint32_t ITER = 3;
constexpr uint32_t LANES = 4;

inline void comprova(int resultat, const char* missatge) {
    if (resultat != 1) throw std::runtime_error(missatge);
}

inline Bytes generarBytesAleatoris(size_t n) {
    Bytes b(n);
    comprova(RAND_bytes(b.data(), static_cast<int>(n)), "RAND_bytes ha fallat");
    return b;
}

inline Bytes argon2id(const std::string& pw, const Bytes& salt, size_t outLen, uint32_t memcost, uint32_t iter, uint32_t lanes) {
    OSSL_PARAM params[6], *p = params;
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_LANES, &lanes);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ARGON2_MEMCOST, &memcost);
    *p++ = OSSL_PARAM_construct_uint32(OSSL_KDF_PARAM_ITER, &iter);
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_SALT, const_cast<unsigned char*>(salt.data()), salt.size());
    *p++ = OSSL_PARAM_construct_octet_string(OSSL_KDF_PARAM_PASSWORD, const_cast<char*>(pw.data()), pw.size());
    *p = OSSL_PARAM_construct_end();

    Bytes out(outLen);
    EVP_KDF* kdf = EVP_KDF_fetch(nullptr, "ARGON2ID", nullptr);
    EVP_KDF_CTX* kctx = kdf ? EVP_KDF_CTX_new(kdf) : nullptr;
    int ok = kctx ? EVP_KDF_derive(kctx, out.data(), out.size(), params) : 0;
    
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
    
    if (ok != 1) throw std::runtime_error("Argon2id ha fallat");
    return out;
}

inline Bytes derivarClau(const std::string& contrasenya, const Bytes& salt) {
    return argon2id(contrasenya, salt, KEY_LEN, MEMCOST, ITER, LANES);
}

struct CtxDeleter { void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); } };
using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

inline Bytes xifrarAES_GCM(const std::string& textClar, const Bytes& clau, const Bytes& iv) {
    if (clau.size() != KEY_LEN || iv.size() != IV_LEN) throw std::invalid_argument("Clau/IV incorrecte");
    CtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("Error context CIPHER");

    Bytes sortida(textClar.size() + TAG_LEN);
    unsigned char final_buf[16];
    int len = 0, total = 0;

    comprova(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "Init");
    comprova(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr), "IV len");
    comprova(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, clau.data(), iv.data()), "Clau/IV");
    comprova(EVP_EncryptUpdate(ctx.get(), sortida.data(), &len, reinterpret_cast<const unsigned char*>(textClar.data()), static_cast<int>(textClar.size())), "Update");
    total = len;
    comprova(EVP_EncryptFinal_ex(ctx.get(), final_buf, &len), "Final");
    total += len;
    comprova(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN, sortida.data() + total), "Tag");
    sortida.resize(static_cast<size_t>(total) + TAG_LEN);
    return sortida;
}

inline std::string desxifrarAES_GCM(const Bytes& textXifrat, const Bytes& clau, const Bytes& iv) {
    if (clau.size() != KEY_LEN || iv.size() != IV_LEN || textXifrat.size() < TAG_LEN) throw std::invalid_argument("Dades incorrectes");
    const size_t ctLen = textXifrat.size() - TAG_LEN;
    CtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("Error context");

    Bytes clar(ctLen);
    unsigned char final_buf[16];
    int len = 0, total = 0;

    comprova(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "Init");
    comprova(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr), "IV len");
    comprova(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, clau.data(), iv.data()), "Clau/IV");
    if (ctLen > 0) {
        comprova(EVP_DecryptUpdate(ctx.get(), clar.data(), &len, textXifrat.data(), static_cast<int>(ctLen)), "Update");
        total = len;
    }
    comprova(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN, const_cast<unsigned char*>(textXifrat.data() + ctLen)), "Set tag");
    if (EVP_DecryptFinal_ex(ctx.get(), final_buf, &len) <= 0) throw std::runtime_error("Contrasenya incorrecta o dades alterades");
    return std::string(clar.begin(), clar.begin() + total);
}

struct StmtDeleter { void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); } };
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

inline StmtPtr preparar(sqlite3* db, const char* sql) {
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &s, nullptr) != SQLITE_OK) throw std::runtime_error(sqlite3_errmsg(db));
    return StmtPtr(s);
}

inline void crearTaules(sqlite3* db) {
    const char* sql =
        "PRAGMA foreign_keys = ON;"
        "CREATE TABLE IF NOT EXISTS usuaris ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, nom TEXT NOT NULL UNIQUE, pw_salt BLOB NOT NULL, pw_hash BLOB NOT NULL, memcost INTEGER NOT NULL, iter INTEGER NOT NULL, lanes INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS secrets ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT, usuari_id INTEGER NOT NULL REFERENCES usuaris(id) ON DELETE CASCADE, nom TEXT NOT NULL, kdf_salt BLOB NOT NULL, iv BLOB NOT NULL, xifrat BLOB NOT NULL, UNIQUE(usuari_id, nom));";
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string m = err ? err : "error"; sqlite3_free(err); throw std::runtime_error(m);
    }
}

inline bool registrarUsuari(sqlite3* db, const std::string& nom, const std::string& pw) {
    Bytes salt = generarBytesAleatoris(SALT_LEN);
    Bytes hash = argon2id(pw, salt, HASH_LEN, MEMCOST, ITER, LANES);
    auto st = preparar(db, "INSERT INTO usuaris(nom,pw_salt,pw_hash,memcost,iter,lanes) VALUES(?,?,?,?,?,?)");
    sqlite3_bind_text(st.get(), 1, nom.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st.get(), 2, salt.data(), static_cast<int>(salt.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st.get(), 3, hash.data(), static_cast<int>(hash.size()), SQLITE_TRANSIENT);
    sqlite3_bind_int64(st.get(), 4, MEMCOST);
    sqlite3_bind_int64(st.get(), 5, ITER);
    sqlite3_bind_int64(st.get(), 6, LANES);
    return sqlite3_step(st.get()) == SQLITE_DONE;
}

inline std::optional<int64_t> loginUsuari(sqlite3* db, const std::string& nom, const std::string& pw) {
    auto st = preparar(db, "SELECT id,pw_salt,pw_hash,memcost,iter,lanes FROM usuaris WHERE nom=?");
    sqlite3_bind_text(st.get(), 1, nom.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st.get()) != SQLITE_ROW) {
        argon2id(pw, generarBytesAleatoris(SALT_LEN), HASH_LEN, MEMCOST, ITER, LANES);
        return std::nullopt;
    }
    int64_t id = sqlite3_column_int64(st.get(), 0);
    const unsigned char* s_ptr = static_cast<const unsigned char*>(sqlite3_column_blob(st.get(), 1));
    Bytes salt(s_ptr, s_ptr + sqlite3_column_bytes(st.get(), 1));
    const unsigned char* h_ptr = static_cast<const unsigned char*>(sqlite3_column_blob(st.get(), 2));
    Bytes esperat(h_ptr, h_ptr + sqlite3_column_bytes(st.get(), 2));
    Bytes calculat = argon2id(pw, salt, esperat.size(),
                              static_cast<uint32_t>(sqlite3_column_int64(st.get(), 3)),
                              static_cast<uint32_t>(sqlite3_column_int64(st.get(), 4)),
                              static_cast<uint32_t>(sqlite3_column_int64(st.get(), 5)));
    if (calculat.size() == esperat.size() && CRYPTO_memcmp(calculat.data(), esperat.data(), calculat.size()) == 0)
        return id;
    return std::nullopt;
}

inline void desarSecret(sqlite3* db, int64_t usuariId, const std::string& nomSecret, const std::string& contrasenya, const std::string& text) {
    Bytes kdfSalt = generarBytesAleatoris(SALT_LEN);
    Bytes iv = generarBytesAleatoris(IV_LEN);
    Bytes clau = derivarClau(contrasenya, kdfSalt);
    Bytes xifrat = xifrarAES_GCM(text, clau, iv);
    OPENSSL_cleanse(clau.data(), clau.size());

    auto st = preparar(db, "INSERT INTO secrets(usuari_id,nom,kdf_salt,iv,xifrat) VALUES(?,?,?,?,?)");
    sqlite3_bind_int64(st.get(), 1, usuariId);
    sqlite3_bind_text(st.get(), 2, nomSecret.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_blob(st.get(), 3, kdfSalt.data(), static_cast<int>(kdfSalt.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st.get(), 4, iv.data(), static_cast<int>(iv.size()), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st.get(), 5, xifrat.data(), static_cast<int>(xifrat.size()), SQLITE_TRANSIENT);
    if (sqlite3_step(st.get()) != SQLITE_DONE) throw std::runtime_error("Secret duplicat o error en desar");
}

inline std::string llegirSecret(sqlite3* db, int64_t usuariId, const std::string& nomSecret, const std::string& contrasenya) {
    auto st = preparar(db, "SELECT kdf_salt,iv,xifrat FROM secrets WHERE usuari_id=? AND nom=?");
    sqlite3_bind_int64(st.get(), 1, usuariId);
    sqlite3_bind_text(st.get(), 2, nomSecret.c_str(), -1, SQLITE_TRANSIENT);
    if (sqlite3_step(st.get()) != SQLITE_ROW) throw std::runtime_error("Secret no trobat");

    const unsigned char* k_ptr = static_cast<const unsigned char*>(sqlite3_column_blob(st.get(), 0));
    Bytes kdfSalt(k_ptr, k_ptr + sqlite3_column_bytes(st.get(), 0));
    const unsigned char* i_ptr = static_cast<const unsigned char*>(sqlite3_column_blob(st.get(), 1));
    Bytes iv(i_ptr, i_ptr + sqlite3_column_bytes(st.get(), 1));
    const unsigned char* x_ptr = static_cast<const unsigned char*>(sqlite3_column_blob(st.get(), 2));
    Bytes xifrat(x_ptr, x_ptr + sqlite3_column_bytes(st.get(), 2));

    Bytes clau = derivarClau(contrasenya, kdfSalt);
    try {
        std::string clar = desxifrarAES_GCM(xifrat, clau, iv);
        OPENSSL_cleanse(clau.data(), clau.size());
        return clar;
    } catch (...) {
        OPENSSL_cleanse(clau.data(), clau.size());
        throw;
    }
}

inline std::vector<std::string> llistarSecrets(sqlite3* db, int64_t usuariId) {
    auto st = preparar(db, "SELECT nom FROM secrets WHERE usuari_id=? ORDER BY nom");
    sqlite3_bind_int64(st.get(), 1, usuariId);
    std::vector<std::string> noms;
    while (sqlite3_step(st.get()) == SQLITE_ROW) {
        const unsigned char* t = sqlite3_column_text(st.get(), 0);
        if (t) noms.emplace_back(reinterpret_cast<const char*>(t));
    }
    return noms;
}

#endif