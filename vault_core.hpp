// vault_core.hpp
#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

void crearTaules(sqlite3* db);

// false si el nom d'usuari ja existeix
bool registrarUsuari(sqlite3* db, const std::string& nom, const std::string& pw);

// id de l'usuari si el login és correcte
std::optional<int64_t> loginUsuari(sqlite3* db, const std::string& nom, const std::string& pw);

void desarSecret(sqlite3* db, int64_t usuariId, const std::string& nomSecret,
                 const std::string& contrasenya, const std::string& text);

// Llença std::runtime_error si el secret no existeix o la contrasenya és incorrecta
std::string llegirSecret(sqlite3* db, int64_t usuariId, const std::string& nomSecret,
                         const std::string& contrasenya);

std::vector<std::string> llistarSecrets(sqlite3* db, int64_t usuariId);
