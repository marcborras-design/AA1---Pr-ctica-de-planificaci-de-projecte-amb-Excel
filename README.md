# Secure Vault

Gestor local de secrets amb interfície web. Cada usuari té un compte i pot guardar textos
**xifrats** que només ell pot desxifrar amb la seva contrasenya.

- **Login:** la contrasenya es guarda com a hash **Argon2id** (amb salt aleatori).
- **Xifratge:** **AES-256-GCM**; la clau es deriva de la contrasenya amb Argon2id (amb un salt
  diferent del del login). Mai es guarda ni la contrasenya ni la clau.
- **Base de dades:** SQLite (`vault.db`, es crea sola).
- **Interfície:** pàgina HTML servida per un petit servidor local en C++. Idiomes: català,
  castellà, anglès i noruec.

El programa només escolta a `127.0.0.1`: no és accessible des d'altres ordinadors.

---

## Requisits

| Cosa | Detall |
|---|---|
| Compilador C++ | Amb suport de C++17 (g++ recomanat) |
| **OpenSSL ≥ 3.2** | Cal per a Argon2. Comprova-ho amb `openssl version` |
| SQLite 3 (llibreria de desenvolupament) | `sqlite3.h` i `libsqlite3` |
| `httplib.h` | Llibreria d'un sol fitxer ([cpp-httplib](https://github.com/yhirose/cpp-httplib), llicència MIT) |
| Un navegador web | Per fer servir la interfície |

> **Atenció amb la versió d'OpenSSL.** Moltes distribucions estables de Linux (per exemple
> Ubuntu 24.04 LTS) porten OpenSSL 3.0.x, que **no té Argon2**. Si és el teu cas, mira la secció
> [Si OpenSSL és massa antic](#si-openssl-és-massa-antic).

### Fitxers del projecte

| Fitxer | Què és |
|---|---|
| `server.cpp` | Servidor web local i API (registre, login, desar, llegir, tancar sessió) |
| `pagina.hpp` | La pàgina HTML (embeguda dins del programa) i les traduccions |
| `vault_core.cpp` / `vault_core.hpp` | Nucli: Argon2id, AES-256-GCM i base de dades |
| `httplib.h` | Servidor HTTP (si no hi és, cal baixar-lo; veure sota) |

---

## Linux

### 1. Instal·lar les dependències

**Debian / Ubuntu:**

```bash
sudo apt install build-essential libssl-dev libsqlite3-dev wget
```

**Fedora:**

```bash
sudo dnf install gcc-c++ openssl-devel sqlite-devel wget
```

**Arch:**

```bash
sudo pacman -S base-devel openssl sqlite wget
```

Comprova la versió d'OpenSSL (ha de ser 3.2 o superior):

```bash
openssl version
```

### 2. Aconseguir `httplib.h`

Si no és a la carpeta del projecte, descarrega'l **a la mateixa carpeta que `server.cpp`**.
Usa una versió recent (les antigues han tingut correccions de seguretat):

```bash
wget https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h
```

### 3. Compilar

```bash
g++ -std=c++17 -O2 -Wall -Wextra -pthread server.cpp vault_core.cpp -o vault_web -lcrypto -lsqlite3
```

### 4. Executar

```bash
./vault_web
```

Veuràs:

```
Secure Vault en marxa. Obre al navegador:
    http://localhost:8080
```

Obre aquesta adreça al navegador. Per aturar el programa: `Ctrl+C`.

---

## Windows

La forma més directa és **MSYS2**, perquè hi ha OpenSSL recent (3.5) i el compilador g++.

### Opció A (recomanada): MSYS2

1. Descarrega i instal·la MSYS2 des de <https://www.msys2.org>.
2. Obre el terminal **"MSYS2 UCRT64"** del menú Inici (no el "MSYS" ni el "MINGW64").
3. Actualitza el sistema (si et demana tancar el terminal, fes-ho i torna'l a obrir):

   ```bash
   pacman -Syu
   ```

4. Instal·la el compilador i les llibreries:

   ```bash
   pacman -S mingw-w64-ucrt-x86_64-toolchain mingw-w64-ucrt-x86_64-openssl mingw-w64-ucrt-x86_64-sqlite3
   ```

5. Ves a la carpeta del projecte. Les unitats de Windows apareixen sota `/c/`, `/d/`...:

   ```bash
   cd /c/Users/EL_TEU_NOM/vault_web
   ```

6. Si no tens `httplib.h` a la carpeta, descarrega'l:

   ```bash
   curl -L -O https://raw.githubusercontent.com/yhirose/cpp-httplib/master/httplib.h
   ```

7. Compila. A Windows calen **dues opcions més** que a Linux (`-D_WIN32_WINNT=0x0A00` i
   `-lws2_32`):

   ```bash
   g++ -std=c++17 -O2 -Wall -Wextra -pthread -D_WIN32_WINNT=0x0A00 server.cpp vault_core.cpp -o vault_web.exe -lcrypto -lsqlite3 -lws2_32
   ```

8. Executa **des del mateix terminal MSYS2 UCRT64**:

   ```bash
   ./vault_web.exe
   ```

9. Obre `http://localhost:8080` al navegador.

> **No facis doble clic a `vault_web.exe`** des de l'Explorador: el programa necessita les DLL
> d'OpenSSL i SQLite que viuen a `C:\msys64\ucrt64\bin`, i sense elles no arrenca. Executa'l des
> del terminal MSYS2, o afegeix aquesta carpeta al `PATH` de Windows, o copia al costat de l'`.exe`
> les DLL que et demani.

### Opció B: WSL (Linux dins de Windows)

1. A PowerShell (com a administrador): `wsl --install`, i reinicia.
2. Obre Ubuntu i segueix la secció **Linux** d'aquest document.

**Compte:** la versió d'Ubuntu que instal·la WSL per defecte sol portar OpenSSL 3.0.x, que no
serveix. Hauràs de compilar OpenSSL tu (veure sota) o triar una distribució amb OpenSSL ≥ 3.2.
Per això l'opció A és més senzilla.

---

## Si OpenSSL és massa antic

Si `openssl version` mostra una versió inferior a 3.2, pots compilar OpenSSL en una carpeta teva
sense tocar el del sistema:

```bash
# 1. Descarrega el tarball de la versió 3.5.x des de https://www.openssl.org/source/
tar xf openssl-3.5.*.tar.gz
cd openssl-3.5.*
./Configure --prefix=$HOME/openssl35 --openssldir=$HOME/openssl35/ssl
make -j"$(nproc)"
make install
cd ..
```

Després compila el projecte indicant on és aquest OpenSSL (`lib` o `lib64` segons el sistema, per
això es posen les dues):

```bash
g++ -std=c++17 -O2 -pthread -I$HOME/openssl35/include server.cpp vault_core.cpp -o vault_web \
    -L$HOME/openssl35/lib64 -L$HOME/openssl35/lib \
    -Wl,-rpath,$HOME/openssl35/lib64 -Wl,-rpath,$HOME/openssl35/lib \
    -lcrypto -lsqlite3
```

---

## Com s'usa

1. **Crear usuari:** pestanya *Crear usuari*. La contrasenya ha de tenir **mínim 8 caràcters amb
   majúscula, minúscula, número i símbol** (la pàgina ho va marcant).
2. **Iniciar sessió** amb aquest usuari i contrasenya.
3. **Desar un secret:** escriu un nom i un text, i prem *Xifrar i desar*.
4. **Llegir un secret:** clica'l a la llista (o escriu el nom) i prem *Desxifrar*.
5. **Canviar d'idioma:** selector a dalt a la dreta (Català, Castellano, English, Norsk).
6. La sessió **caduca als 15 minuts d'inactivitat**.

> Si oblides la contrasenya, **els secrets no es poden recuperar**: la clau es deriva d'ella i no
> es guarda enlloc.

---

## On es guarden les dades

El programa crea `vault.db` al **directori des d'on l'executes**. Conté els hashes de les
contrasenyes i els secrets xifrats.

- **No pugis `vault.db` a GitHub** (afegeix-lo al `.gitignore`, com també l'executable
  `vault_web`).
- Per començar de zero, atura el programa i esborra `vault.db`.
- Per inspeccionar-lo, pots obrir-lo amb DBeaver (no el modifiquis a mà).

---

## Resolució de problemes

| Problema | Causa i solució |
|---|---|
| `httplib.h: No such file or directory` | Falta `httplib.h` a la carpeta (veure pas 2 de Linux). |
| `sqlite3.h: No such file or directory` | Falta el paquet de desenvolupament de SQLite (`libsqlite3-dev`). |
| `openssl/core_names.h: No such file or directory` | Falta el paquet de desenvolupament d'OpenSSL (`libssl-dev`), o la versió és anterior a 3.0. |
| `OSSL_KDF_PARAM_ARGON2_...` no declarat, o el programa diu "error intern" en registrar | OpenSSL anterior a 3.2: veure [Si OpenSSL és massa antic](#si-openssl-és-massa-antic). |
| Port 8080 ocupat | Tens una altra còpia en marxa. Tanca-la, o canvia `PORT` a `server.cpp` i torna a compilar. |
| Pàgina en blanc o amb text antic | Prem `Ctrl+F5` per esborrar la còpia en memòria del navegador. |
| Missatge "Host no permes" | Entra per `http://localhost:8080` o `http://127.0.0.1:8080`, no per la IP de la xarxa. |
| **Windows:** `cpp-httplib doesn't support Windows 8 or lower` o `CreateFile2 has not been declared` | Falta `-D_WIN32_WINNT=0x0A00` a l'ordre de compilació. |
| **Windows:** `undefined reference to ... WSAStartup` (o similar) | Falta `-lws2_32` al final de l'ordre. |
| **Windows:** l'`.exe` no arrenca o diu que falta una DLL | Executa'l des del terminal MSYS2 UCRT64 (veure nota de l'opció A). |

---

## Limitacions

- No hi ha límit d'intents fallits al login (Argon2id frena cada intent, però no els bloqueja).
- El tràfic va per HTTP sense xifrar, però només dins del mateix ordinador (loopback). Si
  s'exposés a una xarxa, caldria HTTPS.
- Els secrets es desen en memòria del servidor només mentre dura la sessió (la contrasenya es
  conserva per derivar les claus, i s'esborra en tancar-la o en caducar).
- La mida màxima d'un secret és d'1 MiB.

## Llicències de tercers

`httplib.h` (cpp-httplib) és de Yuji Hirose, llicència MIT. Si el redistribueixes, conserva
l'avís de copyright que porta a la capçalera.
