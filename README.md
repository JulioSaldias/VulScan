# VulScan

Revisión de señales públicas HTTP/TLS, cookies, archivos expuestos opcionales y coincidencias OSV. Solo para sitios propios o autorizados.

**Ejecutar:** Node.js 22 LTS, `npm ci`, `npm test`, `npm start`. Abrir `http://localhost:3000`.

**Desplegar:** importar este repositorio en Render como Blueprint (`render.yaml`), o construir el Dockerfile en un servidor con HTTPS. El contenedor escucha en `PORT` (3000 por defecto). Endpoint de salud: `/health`. No requiere claves API.

**Seguridad:** DNS validado y fijado por conexión; bloqueo de IP privadas/reservadas, puertos personalizados y credenciales; validación de redirecciones; TLS estricto; tiempos y lecturas limitados; CSP sin scripts inline; no se persisten informes ni valores de cookies o archivos.

**Límites:** 5 análisis/10 minutos por IP de conexión y 3 simultáneos, en memoria por proceso. No se confía en X-Forwarded-For: detrás de un proxy los usuarios pueden compartir cuota. Mantener una sola instancia; antes de escalar, usar un limitador compartido y configurar proxies confiables. Reiniciar restablece cuotas. Los administradores pueden imponer límites adicionales en el proxy.

Modo pasivo: una página, hasta 3 redirecciones. Opción de exposición: 5 GET adicionales (muestras de 4 KiB), sin enumeración ni explotación. Las firmas de archivos requieren confirmación; robots.txt no es una vulnerabilidad por sí mismo. HTML máximo 256 KiB. TLS valida confianza, nombre y vigencia y muestra el protocolo negociado; no prueba todos los cifrados ni revocación.

OSV consulta versiones de jQuery, Bootstrap y Lodash inferidas de URLs del HTML; no ejecuta JS ni descarga dependencias. Las coincidencias son potenciales, con severidad Media provisional. Banners de servidor no permiten confirmar CVE. Los errores aparecen como no verificados. Puntuación orientativa: 100 menos 35/20/8/3 puntos por hallazgo Crítico/Alto/Medio/Bajo; mínimo 0. No es CVSS ni certificación. Respuestas HTTP de error o fallos TLS no reciben puntuación.

Referencias: [Node TLS](https://nodejs.org/api/tls.html), [API OSV](https://google.github.io/osv.dev/post-v1-query/).
