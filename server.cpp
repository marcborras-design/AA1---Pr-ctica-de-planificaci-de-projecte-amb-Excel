// server.cpp - Secure Vault amb interfície HTML
//
// Programa C++ que obre un servidor web LOCAL (només 127.0.0.1) i serveix la
// pàgina HTML. La criptografia i la base de dades segueixen sent C++ (vault_core).
//
// Compilar (cal httplib.h a la mateixa carpeta):
//   g++ -std=c++17 -O2 -Wall -Wextra -pthread server.cpp vault_core.cpp -o vault_web -lcrypto -lsqlite3

#include "httplib.h"
#include "pagina.hpp"
#include "vault_core.hpp"

#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <cctype>
#include <chrono>
#include <cstdio>
#include <iostream>
#include <mutex>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>

constexpr int    PORT           = 8080;
constexpr size_t MAX_NOM_USUARI = 64;
constexpr size_t MAX_PW         = 256;
constexpr size_t MAX_NOM_SECRET = 128;
constexpr size_t MAX_TEXT       = 1 << 20;   // 1 MiB
constexpr auto   CADUCITAT      = std::chrono::minutes(15);

// ---------- Regla de contrasenya (adaptada del codi de la Persona 1) ----------
// Retorna "" si és vàlida, o un codi d'error (el navegador el tradueix).
static std::string errorContrasenya(const std::string& pw) {
    if (pw.size() < 8) return "pw_curta";

    bool maj = false, min = false, num = false, esp = false;
    for (unsigned char c : pw) {            // unsigned char: evita comportament indefinit amb isupper & co.
        if (std::isupper(c))      maj = true;
        else if (std::islower(c)) min = true;
        else if (std::isdigit(c)) num = true;
        else                      esp = true;
    }
    if (!maj || !min || !num || !esp)
        return "pw_complexitat";
    return "";
}

// ---------- JSON (a mà, només el que cal) ----------
static std::string jsonEsc(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  o += "\\\""; break;
            case '\\': o += "\\\\"; break;
            case '\n': o += "\\n";  break;
            case '\r': o += "\\r";  break;
            case '\t': o += "\\t";  break;
            default:
                if (c < 0x20) {
                    char b[8];
                    std::snprintf(b, sizeof b, "\\u%04x", c);
                    o += b;
                } else {
                    o += static_cast<char>(c);
                }
        }
    }
    return o;
}

static std::string jsonErr(const std::string& m, bool caducada = false) {
    return std::string("{\"ok\":false,\"error\":\"") + jsonEsc(m) + "\"" +
           (caducada ? ",\"caducada\":true" : "") + "}";
}

static std::string jsonLlista(const std::vector<std::string>& v) {
    std::string o = "[";
    for (size_t i = 0; i < v.size(); ++i) {
        if (i) o += ",";
        o += "\"" + jsonEsc(v[i]) + "\"";
    }
    return o + "]";
}

static void respon(httplib::Response& res, const std::string& json) {
    res.set_content(json, "application/json; charset=utf-8");
}

static std::string retalla(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

// ---------- Sessions (en memòria del servidor) ----------
struct Sessio {
    int64_t id;
    std::string usuari;
    std::string pw;    // necessària per derivar la clau de cada secret
    std::chrono::steady_clock::time_point ultim;
};

static void esborraPw(std::string& s) {
    if (!s.empty()) OPENSSL_cleanse(&s[0], s.size());
    s.clear();
}

static std::string nouToken() {
    unsigned char b[32];
    if (RAND_bytes(b, sizeof b) != 1) throw std::runtime_error("RAND_bytes ha fallat");
    static const char* hex = "0123456789abcdef";
    std::string t;
    for (unsigned char c : b) { t += hex[c >> 4]; t += hex[c & 15]; }
    return t;
}

using Sessions = std::unordered_map<std::string, Sessio>;

// Retorna la sessió si és vàlida (i en renova el temps), o nullptr
static Sessio* trobaSessio(Sessions& m, const std::string& token) {
    auto it = m.find(token);
    if (it == m.end()) return nullptr;
    auto ara = std::chrono::steady_clock::now();
    if (ara - it->second.ultim > CADUCITAT) {
        esborraPw(it->second.pw);
        m.erase(it);
        return nullptr;
    }
    it->second.ultim = ara;
    return &it->second;
}

int main() {
    sqlite3* db = nullptr;
    if (sqlite3_open("vault.db", &db) != SQLITE_OK) {
        std::cerr << "No s'ha pogut obrir la base de dades.\n";
        return 1;
    }
    try {
        crearTaules(db);
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << "\n";
        sqlite3_close(db);
        return 1;
    }

    std::mutex mtx;          // una sola operació alhora (SQLite + sessions)
    Sessions sessions;

    httplib::Server svr;

    // Defensa bàsica: només acceptem peticions dirigides a localhost (anti DNS-rebinding)
    svr.set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        const std::string host = req.get_header_value("Host");
        if (host != "127.0.0.1:" + std::to_string(PORT) &&
            host != "localhost:" + std::to_string(PORT)) {
            res.status = 403;
            res.set_content("Host no permes", "text/plain");
            return httplib::Server::HandlerResponse::Handled;
        }
        res.set_header("Cache-Control", "no-store");
        res.set_header("X-Content-Type-Options", "nosniff");
        res.set_header("Content-Security-Policy",
            "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'");
        return httplib::Server::HandlerResponse::Unhandled;
    });

    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(PAGINA_HTML, "text/html; charset=utf-8");
    });

    // ---- Registre ----
    svr.Post("/api/registre", [&](const httplib::Request& req, httplib::Response& res) {
        std::string nom = retalla(req.get_param_value("usuari"));
        std::string pw  = req.get_param_value("contrasenya");
        std::string pw2 = req.get_param_value("repeteix");

        std::string error;
        if (nom.empty() || nom.size() > MAX_NOM_USUARI)
            error = "usuari_invalid";
        else if (pw.size() > MAX_PW)
            error = "pw_llarga";
        else if (pw != pw2)
            error = "pw_no_coincideix";
        else
            error = errorContrasenya(pw);
        if (!error.empty()) { respon(res, jsonErr(error)); return; }

        std::lock_guard<std::mutex> lk(mtx);
        try {
            if (registrarUsuari(db, nom, pw)) respon(res, "{\"ok\":true}");
            else respon(res, jsonErr("usuari_existeix"));
        } catch (const std::exception& e) {
            std::cerr << "registre: " << e.what() << "\n";
            respon(res, jsonErr("error_intern"));
        }
    });

    // ---- Login ----
    svr.Post("/api/login", [&](const httplib::Request& req, httplib::Response& res) {
        std::string nom = retalla(req.get_param_value("usuari"));
        std::string pw  = req.get_param_value("contrasenya");
        const std::string credencialsMalament = "credencials";

        if (nom.empty() || nom.size() > MAX_NOM_USUARI || pw.empty() || pw.size() > MAX_PW) {
            respon(res, jsonErr(credencialsMalament));
            return;
        }

        std::lock_guard<std::mutex> lk(mtx);
        try {
            auto id = loginUsuari(db, nom, pw);
            if (!id) { respon(res, jsonErr(credencialsMalament)); return; }

            std::string token = nouToken();
            sessions[token] = Sessio{*id, nom, pw, std::chrono::steady_clock::now()};
            respon(res, "{\"ok\":true,\"token\":\"" + token + "\",\"usuari\":\"" + jsonEsc(nom) +
                        "\",\"secrets\":" + jsonLlista(llistarSecrets(db, *id)) + "}");
        } catch (const std::exception& e) {
            std::cerr << "login: " << e.what() << "\n";
            respon(res, jsonErr("error_intern"));
        }
    });

    // ---- Desar un secret ----
    svr.Post("/api/desar", [&](const httplib::Request& req, httplib::Response& res) {
        std::string nom  = retalla(req.get_param_value("nom"));
        std::string text = req.get_param_value("text");

        std::lock_guard<std::mutex> lk(mtx);
        Sessio* s = trobaSessio(sessions, req.get_header_value("X-Token"));
        if (!s) { respon(res, jsonErr("sessio_caducada", true)); return; }

        if (nom.empty() || nom.size() > MAX_NOM_SECRET) {
            respon(res, jsonErr("nom_secret_invalid"));
            return;
        }
        if (text.size() > MAX_TEXT) { respon(res, jsonErr("text_gran")); return; }

        try {
            desarSecret(db, s->id, nom, s->pw, text);
            respon(res, "{\"ok\":true,\"secrets\":" + jsonLlista(llistarSecrets(db, s->id)) + "}");
        } catch (const std::exception& e) {
            std::cerr << "desar: " << e.what() << "\n";
            respon(res, jsonErr("desar_error"));
        }
    });

    // ---- Llegir un secret ----
    svr.Post("/api/llegir", [&](const httplib::Request& req, httplib::Response& res) {
        std::string nom = retalla(req.get_param_value("nom"));

        std::lock_guard<std::mutex> lk(mtx);
        Sessio* s = trobaSessio(sessions, req.get_header_value("X-Token"));
        if (!s) { respon(res, jsonErr("sessio_caducada", true)); return; }

        try {
            std::string clar = llegirSecret(db, s->id, nom, s->pw);
            respon(res, "{\"ok\":true,\"text\":\"" + jsonEsc(clar) + "\"}");
        } catch (const std::exception& e) {
            std::cerr << "llegir: " << e.what() << "\n";
            const std::string m = e.what();
            std::string codi = "error_intern";
            if (m == "Secret no trobat") codi = "secret_no_trobat";
            else if (m == "Contrasenya incorrecta o dades alterades") codi = "dades_alterades";
            respon(res, jsonErr(codi));
        }
    });

    // ---- Tancar sessió ----
    svr.Post("/api/logout", [&](const httplib::Request& req, httplib::Response& res) {
        std::lock_guard<std::mutex> lk(mtx);
        auto it = sessions.find(req.get_header_value("X-Token"));
        if (it != sessions.end()) {
            esborraPw(it->second.pw);
            sessions.erase(it);
        }
        respon(res, "{\"ok\":true}");
    });

    std::cout << "Secure Vault en marxa. Obre al navegador:\n"
              << "    http://localhost:" << PORT << "\n"
              << "(Ctrl+C per aturar el programa)\n";

    if (!svr.listen("127.0.0.1", PORT)) {   // només accessible des d'aquest ordinador
        std::cerr << "No s'ha pogut escoltar al port " << PORT << " (ocupat?).\n";
        sqlite3_close(db);
        return 1;
    }
    sqlite3_close(db);
    return 0;
}
