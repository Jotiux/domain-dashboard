# Dashboard de Consulta de Dominios (demo gratuita)

Ingresa un dominio y obtén: fecha de expiración, listas negras, registros MX,
SPF y DMARC. Construido con Next.js para desplegarse gratis en Vercel.

## Cómo subirlo a GitHub (sin usar comandos)

1. Descomprime este archivo .zip en tu computadora.
2. Entra a https://github.com y crea un repositorio nuevo (botón "New repository"),
   por ejemplo llamado `domain-dashboard`. Puede ser público o privado, no importa.
3. En la página del repositorio recién creado, haz clic en "uploading an existing file".
4. Arrastra TODA la carpeta descomprimida (o todos sus archivos) a esa pantalla
   y dale "Commit changes". (No subas las carpetas `node_modules` ni `.next` si
   las ves — no son necesarias, Vercel las genera solo).

## Cómo conectarlo a Vercel

1. Entra a https://vercel.com con tu cuenta.
2. Clic en "Add New..." → "Project".
3. Elige "Import Git Repository" y selecciona el repositorio que acabas de crear.
4. Vercel detecta automáticamente que es un proyecto Next.js — no cambies nada,
   solo dale clic en "Deploy".
5. En 1-2 minutos te da una URL pública tipo `domain-dashboard-tuusuario.vercel.app`,
   ya funcionando y gratis.

Cada vez que subas un cambio nuevo al repositorio de GitHub, Vercel vuelve a
desplegar la página sola, automáticamente.

## Cómo probarlo en tu computadora antes de subirlo (opcional)

Si tienes Node.js instalado:

```
npm install
npm run dev
```

Y abre http://localhost:3000

## De dónde sale cada dato

- **Fecha de expiración**: consulta RDAP pública (rdap.org), el reemplazo
  moderno y gratuito de WHOIS.
- **MX, SPF, DMARC**: consultas DNS directas (no requieren ninguna clave ni
  servicio de pago).
- **Listas negras**: consulta contra Spamhaus DBL y SURBL, dos listas negras
  públicas de uso gratuito, también vía DNS.

Todo esto corre en la función serverless `pages/api/lookup.js`, que Vercel
despliega automáticamente sin que tengas que configurar ningún servidor.
