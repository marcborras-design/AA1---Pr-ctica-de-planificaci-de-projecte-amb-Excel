// vault.cpp
// Login (hash Argon2id) + xifratge (AES-256-GCM amb clau derivada de la contrasenya)
// + emmagatzematge a SQLite. Tot amb OpenSSL >= 3.2 (Argon2).
//
// Compilar a Windows (MSYS2 UCRT64):
// g++ -std=c++17 -Wall -Wextra vault.cpp -o vault.exe -lcrypto -lsqlite3
//
// Compilar a Linux:
// g++ -std=c++17 -Wall -Wextra vault.cpp -o vault -lcrypto -lsqlite3

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/params.h>
#include <openssl/rand.h>
#include <sqlite3.h>

#ifdef _WIN32
  #include <windows.h>
  #include <io.h>
#else
  #include <termios.h>
  #include <unistd.h>
#endif

#include <climits>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

using Bytes = std::vector<unsigned char>;

// ======================= Constants =======================
constexpr size_t SALT_LEN = 16;
constexpr size_t IV_LEN = 12;   // mida estàndard per a GCM
constexpr size_t KEY_LEN = 32;  // AES-256
constexpr size_t TAG_LEN = 16;
constexpr size_t HASH_LEN = 32; // longitud del hash de login

// Cost d'Argon2id (memcost en blocs d'1 KiB)
constexpr uint32_t MEMCOST = 65536;
constexpr uint32_t ITER = 3;
constexpr uint32_t LANES = 4;

static void comprova(int resultat, const char* missatge) {
    if (resultat != 1) throw std::runtime_error(missatge);
}

// ======================= 1. Aleatoris =======================
Bytes generarBytesAleatoris(size_t n) {
    Bytes b(n);
    comprova(RAND_bytes(b.data(), static_cast<int>(n)), "RAND_bytes ha fallat");
    return b;
}

Bytes generarSaltAleatori(size_t n) {
    return generarBytesAleatoris(n);
}

Bytes generarIVAleatori(size_t n) {
    return generarBytesAleatoris(n);
}

// ======================= 2. Argon2id =======================
Bytes argon2id(const std::string& pw, const Bytes& salt, size_t outLen, uint32_t memcost, uint32_t iter, uint32_t lanes) {
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

Bytes derivarClau(const std::string& contrasenya, const Bytes& salt) {
    return argon2id(contrasenya, salt, KEY_LEN, MEMCOST, ITER, LANES);
}

// ======================= 3. AES-256-GCM =======================
struct CtxDeleter {
    void operator()(EVP_CIPHER_CTX* c) const { EVP_CIPHER_CTX_free(c); }
};
using CtxPtr = std::unique_ptr<EVP_CIPHER_CTX, CtxDeleter>;

Bytes xifrarAES_GCM(const std::string& textClar, const Bytes& clau, const Bytes& iv) {
    if (clau.size() != KEY_LEN || iv.size() != IV_LEN) throw std::invalid_argument("Clau o IV amb mida incorrecta");
    if (textClar.size() > static_cast<size_t>(INT_MAX)) throw std::invalid_argument("Text massa gran");

    CtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("No s'ha pogut crear el context");

    Bytes sortida(textClar.size() + TAG_LEN);
    unsigned char final_buf[16];
    int len = 0, total = 0;

    comprova(EVP_EncryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "Init");
    comprova(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr), "IV len");
    comprova(EVP_EncryptInit_ex(ctx.get(), nullptr, nullptr, clau.data(), iv.data()), "Clau/IV");
    comprova(EVP_EncryptUpdate(ctx.get(), sortida.data(), &len,
                               reinterpret_cast<const unsigned char*>(textClar.data()),
                               static_cast<int>(textClar.size())), "Update");
    total = len;
    comprova(EVP_EncryptFinal_ex(ctx.get(), final_buf, &len), "Final");
    total += len;

    comprova(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_GET_TAG, TAG_LEN,
                                 sortida.data() + total), "Tag");
    sortida.resize(static_cast<size_t>(total) + TAG_LEN);
    return sortida;
}

std::string desxifrarAES_GCM(const Bytes& textXifrat, const Bytes& clau, const Bytes& iv) {
    if (clau.size() != KEY_LEN || iv.size() != IV_LEN || textXifrat.size() < TAG_LEN) throw std::invalid_argument("Dades amb mida incorrecta");

    const size_t ctLen = textXifrat.size() - TAG_LEN;
    if (ctLen > static_cast<size_t>(INT_MAX)) throw std::invalid_argument("Massa gran");

    CtxPtr ctx(EVP_CIPHER_CTX_new());
    if (!ctx) throw std::runtime_error("No s'ha pogut crear el context");

    Bytes clar(ctLen);
    unsigned char final_buf[16];
    int len = 0, total = 0;

    comprova(EVP_DecryptInit_ex(ctx.get(), EVP_aes_256_gcm(), nullptr, nullptr, nullptr), "Init");
    comprova(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr), "IV len");
    comprova(EVP_DecryptInit_ex(ctx.get(), nullptr, nullptr, clau.data(), iv.data()), "Clau/IV");
    if (ctLen > 0) {
        comprova(EVP_DecryptUpdate(ctx.get(), clar.data(), &len,
                                   textXifrat.data(), static_cast<int>(ctLen)), "Update");
        total = len;
    }
    comprova(EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                                 const_cast<unsigned char*>(textXifrat.data() + ctLen)), "Set tag");

    if (EVP_DecryptFinal_ex(ctx.get(), final_buf, &len) <= 0)
        throw std::runtime_error("Contrasenya incorrecta o dades alterades");

    return std::string(clar.begin(), clar.begin() + total);
}

// ======================= 4. SQLite: utilitats =======================
struct StmtDeleter {
    void operator()(sqlite3_stmt* s) const { sqlite3_finalize(s); }
};
using StmtPtr = std::unique_ptr<sqlite3_stmt, StmtDeleter>;

static StmtPtr preparar(sqlite3* db, const char* sql) {
    sqlite3_stmt* s = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &s, nullptr) != SQLITE_OK)
        throw std::runtime_error(std::string("SQL: ") + sqlite3_errmsg(db));
    return StmtPtr(s);
}

static void bindBlob(sqlite3_stmt* s, int i, const Bytes& b) {
    sqlite3_bind_blob(s, i, b.data(), static_cast<int>(b.size()), SQLITE_TRANSIENT);
}

static void bindText(sqlite3_stmt* s, int i, const std::string& t) {
    sqlite3_bind_text(s, i, t.c_str(), -1, SQLITE_TRANSIENT);
}

static Bytes colBlob(sqlite3_stmt* s, int i) {
    const unsigned char* p = static_cast<const unsigned char*>(sqlite3_column_blob(s, i));
    int n = sqlite3_column_bytes(s, i);
    return p ? Bytes(p, p + n) : Bytes();
}

void crearTaules(sqlite3* db) {
    const char* sql =
        "PRAGMA foreign_keys = ON;"
        "CREATE TABLE IF NOT EXISTS usuaris ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " nom TEXT NOT NULL UNIQUE,"
        " pw_salt BLOB NOT NULL, pw_hash BLOB NOT NULL,"
        " memcost INTEGER NOT NULL, iter INTEGER NOT NULL, lanes INTEGER NOT NULL);"
        "CREATE TABLE IF NOT EXISTS secrets ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " usuari_id INTEGER NOT NULL REFERENCES usuaris(id) ON DELETE CASCADE,"
        " nom TEXT NOT NULL,"
        " kdf_salt BLOB NOT NULL, iv BLOB NOT NULL, xifrat BLOB NOT NULL,"
        " UNIQUE(usuari_id, nom));";
    char* err = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &err) != SQLITE_OK) {
        std::string m = err ? err : "error desconegut";
        sqlite3_free(err);
        throw std::runtime_error("Crear taules: " + m);
    }
}

// ======================= 5. Usuaris =======================
bool registrarUsuari(sqlite3* db, const std::string& nom, const std::string& pw) {
    Bytes salt = generarSaltAleatori(SALT_LEN);
    Bytes hash = argon2id(pw, salt, HASH_LEN, MEMCOST, ITER, LANES);

    auto st = preparar(db, "INSERT INTO usuaris(nom,pw_salt,pw_hash,memcost,iter,lanes) VALUES(?,?,?,?,?,?)");
    bindText(st.get(), 1, nom);
    bindBlob(st.get(), 2, salt);
    bindBlob(st.get(), 3, hash);
    sqlite3_bind_int64(st.get(), 4, MEMCOST);
    sqlite3_bind_int64(st.get(), 5, ITER);
    sqlite3_bind_int64(st.get(), 6, LANES);
    return sqlite3_step(st.get()) == SQLITE_DONE;
}

std::optional<int64_t> loginUsuari(sqlite3* db, const std::string& nom, const std::string& pw) {
    auto st = preparar(db, "SELECT id,pw_salt,pw_hash,memcost,iter,lanes FROM usuaris WHERE nom=?");
    bindText(st.get(), 1, nom);

    if (sqlite3_step(st.get()) != SQLITE_ROW) {
        argon2id(pw, generarSaltAleatori(SALT_LEN), HASH_LEN, MEMCOST, ITER, LANES);
        return std::nullopt;
    }
    int64_t id = sqlite3_column_int64(st.get(), 0);
    Bytes salt = colBlob(st.get(), 1);
    Bytes esperat = colBlob(st.get(), 2);
    Bytes calculat = argon2id(pw, salt, esperat.size(),
                              static_cast<uint32_t>(sqlite3_column_int64(st.get(), 3)),
                              static_cast<uint32_t>(sqlite3_column_int64(st.get(), 4)),
                              static_cast<uint32_t>(sqlite3_column_int64(st.get(), 5)));

    bool ok = calculat.size() == esperat.size() &&
              CRYPTO_memcmp(calculat.data(), esperat.data(), calculat.size()) == 0;
    if (!ok) return std::nullopt;
    return id;
}

// ======================= 6. Secrets xifrats =======================
void desarSecret(sqlite3* db, int64_t usuariId, const std::string& nomSecret, const std::string& contrasenya, const std::string& text) {
    Bytes kdfSalt = generarSaltAleatori(SALT_LEN);
    Bytes iv = generarIVAleatori(IV_LEN);
    Bytes clau = derivarClau(contrasenya, kdfSalt);
    Bytes xifrat = xifrarAES_GCM(text, clau, iv);
    OPENSSL_cleanse(clau.data(), clau.size());

    auto st = preparar(db, "INSERT INTO secrets(usuari_id,nom,kdf_salt,iv,xifrat) VALUES(?,?,?,?,?)");
    sqlite3_bind_int64(st.get(), 1, usuariId);
    bindText(st.get(), 2, nomSecret);
    bindBlob(st.get(), 3, kdfSalt);
    bindBlob(st.get(), 4, iv);
    bindBlob(st.get(), 5, xifrat);
    if (sqlite3_step(st.get()) != SQLITE_DONE)
        throw std::runtime_error("No s'ha pogut desar (nom duplicat?)");
}

std::string llegirSecret(sqlite3* db, int64_t usuariId, const std::string& nomSecret, const std::string& contrasenya) {
    auto st = preparar(db, "SELECT kdf_salt,iv,xifrat FROM secrets WHERE usuari_id=? AND nom=?");
    sqlite3_bind_int64(st.get(), 1, usuariId);
    bindText(st.get(), 2, nomSecret);
    if (sqlite3_step(st.get()) != SQLITE_ROW) throw std::runtime_error("Secret no trobat");

    Bytes kdfSalt = colBlob(st.get(), 0);
    Bytes iv = colBlob(st.get(), 1);
    Bytes xifrat = colBlob(st.get(), 2);
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

// ======================= 7. Llistat de secrets =======================
std::vector<std::string> llistarSecrets(sqlite3* db, int64_t usuariId) {
    auto st = preparar(db, "SELECT nom FROM secrets WHERE usuari_id=? ORDER BY nom");
    sqlite3_bind_int64(st.get(), 1, usuariId);
    std::vector<std::string> noms;
    while (sqlite3_step(st.get()) == SQLITE_ROW) {
        const unsigned char* t = sqlite3_column_text(st.get(), 0);
        if (t) noms.emplace_back(reinterpret_cast<const char*>(t));
    }
    return noms;
}

// ======================= 8. Interfície de terminal =======================
static std::string llegirLinia(const std::string& missatge) {
    std::cout << missatge << std::flush;
    std::string s;
    if (!std::getline(std::cin, s)) throw std::runtime_error("Entrada tancada");
    return s;
}

// Llegeix una contrasenya SENSE mostrar-la per pantalla (Compatibilitat Linux i Windows)
static std::string llegirContrasenya(const std::string& missatge) {
    std::cout << missatge << std::flush;
    std::string pw;

#ifdef _WIN32
    HANDLE hInput = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hInput, &mode);
    SetConsoleMode(hInput, mode & ~ENABLE_ECHO_INPUT);
    bool ok = static_cast<bool>(std::getline(std::cin, pw));
    SetConsoleMode(hInput, mode);
    std::cout << "\n";
#else
    termios antic{}, nou{};
    bool tty = isatty(STDIN_FILENO) && tcgetattr(STDIN_FILENO, &antic) == 0;
    if (tty) {
        nou = antic;
        nou.c_lflag &= ~static_cast<tcflag_t>(ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &nou);
    }
    bool ok = static_cast<bool>(std::getline(std::cin, pw));
    if (tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &antic);
        std::cout << "\n";
    }
#endif

    if (!ok) throw std::runtime_error("Entrada tancada");
    return pw;
}

static void neteja(std::string& s) {
    if (!s.empty()) OPENSSL_cleanse(&s[0], s.size());
    s.clear();
}

static void menuRegistre(sqlite3* db) {
    std::string nom = llegirLinia("Nom d'usuari nou: ");
    if (nom.empty()) {
        std::cout << "El nom no pot ser buit.\n";
        return;
    }

    std::string pw1 = llegirContrasenya("Contrasenya (minim 8 caracters): ");
    std::string pw2 = llegirContrasenya("Repeteix la contrasenya: ");

    if (pw1 != pw2) std::cout << "Les contrasenyes no coincideixen.\n";
    else if (pw1.size() < 8) std::cout << "Massa curta (minim 8 caracters).\n";
    else {
        std::cout << "Creant usuari...\n";
        if (registrarUsuari(db, nom, pw1)) std::cout << "Usuari creat. Ja pots fer login.\n";
        else std::cout << "Aquest nom d'usuari ja existeix.\n";
    }
    neteja(pw1);
    neteja(pw2);
}

static void menuSessio(sqlite3* db, int64_t id, const std::string& usuari, const std::string& pw) {
    while (true) {
        std::cout << "\n--- Sessio de " << usuari << " ---\n"
                  << "1. Desar un secret nou\n"
                  << "2. Llegir un secret\n"
                  << "3. Llistar els meus secrets\n"
                  << "0. Tancar sessio\n";
        std::string op = llegirLinia("Opcio: ");

        try {
            if (op == "0") return;
            else if (op == "1") {
                std::string nom = llegirLinia("Nom del secret: ");
                if (nom.empty()) { std::cout << "El nom no pot ser buit.\n"; continue; }
                std::string text = llegirLinia("Text a xifrar (una sola linia): ");
                std::cout << "Xifrant...\n";
                desarSecret(db, id, nom, pw, text);
                std::cout << "Secret desat.\n";
            } else if (op == "2") {
                std::string nom = llegirLinia("Nom del secret: ");
                std::cout << "Desxifrant...\n";
                std::cout << "Contingut: " << llegirSecret(db, id, nom, pw) << "\n";
            } else if (op == "3") {
                auto noms = llistarSecrets(db, id);
                if (noms.empty()) std::cout << "Encara no tens cap secret.\n";
                for (const auto& n : noms) std::cout << " - " << n << "\n";
            } else {
                std::cout << "Opcio no valida.\n";
            }
        } catch (const std::runtime_error& e) {
            if (std::string(e.what()) == "Entrada tancada") throw;
            std::cout << "Error: " << e.what() << "\n";
        }
    }
}

int main() {
    sqlite3* db = nullptr;
    try {
        if (sqlite3_open("vault.db", &db) != SQLITE_OK) throw std::runtime_error("No s'ha pogut obrir la base de dades");
        crearTaules(db);

        while (true) {
            std::cout << "\n=== SECURE VAULT ===\n"
                      << "1. Crear usuari\n"
                      << "2. Iniciar sessio\n"
                      << "0. Sortir\n";
            std::string op = llegirLinia("Opcio: ");

            if (op == "0") break;
            else if (op == "1") menuRegistre(db);
            else if (op == "2") {
                std::string nom = llegirLinia("Usuari: ");
                std::string pw = llegirContrasenya("Contrasenya: ");
                std::cout << "Verificant...\n";
                auto id = loginUsuari(db, nom, pw);
                if (!id) std::cout << "Usuari o contrasenya incorrectes.\n";
                else menuSessio(db, *id, nom, pw);
                neteja(pw);
            } else {
                std::cout << "Opcio no valida.\n";
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << "\n";
        sqlite3_close(db);
        return 1;
    }
    sqlite3_close(db);
    return 0;
}