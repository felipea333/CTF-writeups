# Auditoría de Seguridad — Red Corporativa (Trabajo Final Master D)

**Tipo:** Pentest interno de caja gris sobre una red simulada de dos servidores interconectados
**Entorno:** Red NAT 10.0.2.0/24 (laboratorio VirtualBox)
**Rol:** Auditor de seguridad

> Nota: las contraseñas, hashes y flags de este informe han sido redactados. El objetivo del writeup es documentar la metodología y el razonamiento de la auditoría, no exponer credenciales reales ni servir de solucionario literal para quienes cursen el mismo examen.

## Resumen ejecutivo

Auditoría de seguridad sobre una red corporativa simulada compuesta por dos servidores:

| Activo | IP | Rol |
|---|---|---|
| LINUX_MD | 10.0.2.8 | Debian 9 — portal corporativo (Apache + WordPress 5.2.3, FTP, SSH) |
| WS2012_MD | 10.0.2.7 | Windows Server 2012 R2 — archivos (SMB), base de datos (MariaDB), administración remota (WinRM), WordPress local sobre WAMP |

Se obtuvo **control total (root / NT AUTHORITY\SYSTEM) de ambos servidores**. El hallazgo más relevante a nivel organizativo fue la **reutilización de una misma contraseña de administrador** entre Windows, MySQL/WAMP y WordPress — comprometer un solo servicio permitió arrastrar el resto de la infraestructura.

## Resumen de vulnerabilidades

| Máquina | Total | Crítica | Alta | Media | Baja | Informativa |
|---|---|---|---|---|---|---|
| LINUX_MD | 12 | 5 | 3 | 2 | 1 | 1 |
| WS2012 | 12 | 2 | 6 | 2 | 1 | 1 |

## Descripción de la red y relación entre activos

Los dos servidores se ven entre sí dentro de la misma red NAT, lo cual resultó clave para la cadena de ataque: al atacar el WordPress de LINUX_MD directamente desde Kali, el `fail2ban` configurado en Apache detectó el volumen de peticiones y bloqueó la IP del atacante. Esto obligó a **pivotar a través de WS2012** (ya comprometido) para continuar el ataque contra Linux por HTTP, evitando así el bloqueo aplicado sobre la IP original.

Además, la contraseña de administración de Windows resultó estar **reutilizada** en la configuración de MySQL/WAMP y en WordPress, por lo que comprometer un único servicio facilitó el acceso al resto.

## Cadena de ataque — LINUX_MD (10.0.2.8)

**Servicios:** FTP, SSH, HTTP (Apache + WordPress)

1. **Acceso FTP anónimo** — el servidor permitía login anónimo, exponiendo el código fuente completo de WordPress, incluyendo `wp-config.php`.
2. **Lectura de `wp-config.php`** — extracción de credenciales de la base de datos (usuario, contraseña y host de MySQL) directamente del archivo de configuración descargado por FTP.
3. **Inyección SQL** — explotada contra la base de datos de WordPress para extraer el hash de contraseña del usuario administrador.
4. **Descifrado del hash** — crackeo offline del hash extraído.
5. **Carga de plugin malicioso (webshell)** — con las credenciales de administrador de WordPress recuperadas, se subió un plugin modificado para obtener ejecución de comandos en el servidor.
6. **Escalada por reutilización de contraseña** — la contraseña de administración de sistema, reutilizada entre servicios, permitió escalar de acceso web (www-data) a acceso root.

**Resultado:** control total del servidor (root), acceso a flags de usuario y root.

## Cadena de ataque — WS2012 (10.0.2.7)

**Servicios:** SMB, WinRM, HTTP, MariaDB

1. **Credenciales SMB válidas** — obtenidas durante la fase de reconocimiento/enumeración.
2. **Explotación de MS17-010 / EternalBlue (CVE-2017-0144)** — usando el módulo `windows/smb/ms17_010_psexec` de Metasploit junto con las credenciales SMB válidas, se obtuvo una sesión Meterpreter con privilegios **NT AUTHORITY\SYSTEM** de forma inmediata.
3. **Extracción de hashes SAM** — volcado de los hashes de todas las cuentas locales del sistema (`hashdump`).
4. **Pass-the-Hash** — se confirmó que los hashes extraídos permitían autenticación contra el servicio SMB sin necesidad de conocer la contraseña en texto claro, confirmando el compromiso total y persistente del servidor.

**Resultado:** compromiso total e inmediato del servidor.

## Herramientas utilizadas

`Nmap` · `FTP` (cliente) · `NetExec` · `Metasploit Framework` (módulo `ms17_010_psexec`) · Herramientas de inyección SQL y crackeo de hashes · Meterpreter

## Valoración y recomendaciones

La seguridad de la red auditada se encontró **muy por debajo de lo aceptable**, con control completo obtenido sobre ambos servidores.

Recomendaciones principales:
- **Parchear de inmediato** vulnerabilidades críticas y altas — en particular MS17-010, sin parche disponible desde 2017.
- **Eliminar el acceso FTP anónimo** y restringir el listado de directorios.
- **Eliminar la reutilización de contraseñas** entre servicios y sistemas — una política de gestión de identidades (IAM) evitaría que el compromiso de un solo servicio arrastre el resto de la infraestructura.
- **Endurecer la configuración de WordPress**, incluyendo permisos de archivos y validación de plugins.
- **Repetir la auditoría** tras aplicar las correcciones, para verificar su efectividad real.

---

*Auditoría realizada como Trabajo Final del curso de Ethical Hacking (Master D).*
