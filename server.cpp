#ifndef _WIN32_WINNT
  #define _WIN32_WINNT 0x0A00
#endif

#include "httplib.h"
#include "vault_core.hpp"
#include <fstream>
#include <iostream>
#include <sstream>

std::string carregarHTML() {
    std::ifstream f("index.html");
    if (!f.is_open()) return "<h1>Error: No s'ha trobat el fitxer index.html</h1>";
    std::stringstream buffer;
    buffer << f.rdbuf();
    return buffer.str();
}

int main() {
    sqlite3* db = nullptr;
    if (sqlite3_open("vault.db", &db) != SQLITE_OK) {
        std::cerr << "Error obrint la BD\n";
        return 1;
    }
    crearTaules(db);

    httplib::Server svr;

    svr.Get("/", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(carregarHTML(), "text/html");
    });

    svr.Get("/api/register", [db](const httplib::Request& req, httplib::Response& res) {
        std::string u = req.get_param_value("u");
        std::string p = req.get_param_value("p");
        if (u.empty() || p.length() < 8) {
            res.set_content("Usuari o contrasenya invalida (min 8 caracters)", "text/plain");
            return;
        }
        if (registrarUsuari(db, u, p)) res.set_content("Usuari registrat correctament!", "text/plain");
        else res.set_content("L'usuari ja existeix", "text/plain");
    });

    svr.Get("/api/login", [db](const httplib::Request& req, httplib::Response& res) {
        std::string u = req.get_param_value("u");
        std::string p = req.get_param_value("p");
        auto id = loginUsuari(db, u, p);
        if (id) res.set_content("OK", "text/plain");
        else res.set_content("Credencials incorrectes", "text/plain");
    });

    svr.Get("/api/save", [db](const httplib::Request& req, httplib::Response& res) {
        std::string u = req.get_param_value("u");
        std::string p = req.get_param_value("p");
        std::string name = req.get_param_value("name");
        std::string val = req.get_param_value("val");
        auto id = loginUsuari(db, u, p);
        if (!id) { res.set_content("Error d'autenticacio", "text/plain"); return; }
        try {
            desarSecret(db, *id, name, p, val);
            res.set_content("Secret desat correctament!", "text/plain");
        } catch (const std::exception& e) {
            res.set_content(e.what(), "text/plain");
        }
    });

    svr.Get("/api/read", [db](const httplib::Request& req, httplib::Response& res) {
        std::string u = req.get_param_value("u");
        std::string p = req.get_param_value("p");
        std::string name = req.get_param_value("name");
        auto id = loginUsuari(db, u, p);
        if (!id) { res.set_content("Error d'autenticacio", "text/plain"); return; }
        try {
            std::string clar = llegirSecret(db, *id, name, p);
            res.set_content(clar, "text/plain");
        } catch (const std::exception& e) {
            res.set_content(e.what(), "text/plain");
        }
    });

    std::cout << "Servidor gràfic actiu a: http://localhost:8080\n";
    svr.listen("0.0.0.0", 8080);

    sqlite3_close(db);
    return 0;
}