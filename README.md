# ![Juice Shop Logo](https://raw.githubusercontent.com/juice-shop/juice-shop/master/frontend/src/assets/public/images/JuiceShop_Logo_100px.png) OWASP Juice Shop

# DevSecOps & AppSec CI/CD Pipeline Lab

Pipeline automatizado de seguridad implementado sobre OWASP Juice Shop en GitHub Actions para validar detección estática (SAST), análisis de composición y contenedores (SCA) y pruebas dinámicas (DAST) en un ciclo de vida Shift-Left.

---

## 1. Arquitectura del Pipeline

El workflow ejecuta tres capas defensivas automatizadas y desacopladas en runners efímeros de Ubuntu:

* **SAST (Static Application Security Testing):** Semgrep OSS ejecutando reglas comunitarias sobre el código fuente TypeScript/JavaScript y manifiestos IaC/CI.
* **SCA & Container Security:** Trivy (Aqua Security) auditando dependencias en el filesystem (`package.json`), el sistema operativo base de la imagen Docker (`debian 13.7`) y detectando secretos en reposo.
* **DAST (Dynamic Application Security Testing):** Despliegue dinámico del contenedor en el runner local (`localhost:3000`) y auditoría con OWASP ZAP Baseline Scan para identificar configuraciones erróneas en tiempo de ejecución.

---

## 2. Resumen Ejecutivo de Hallazgos

| Herramienta | Tipo | Alcance | Severidad Máxima | Hallazgo Destacado                                |
| :--- | :--- | :--- | :--- | :--- |
| **Semgrep OSS** | SAST | Código Fuente / Workflows | **ERROR (High)** | SQL Injection en Sequelize (`login.ts`)           |
| **Trivy** | Secret Scanning | Filesystem & Docker Image | **HIGH** | Clave privada RSA hardcodeada (`insecurity.ts`)   |
| **Trivy** | SCA | Dependencias Node.js | **CRITICAL** | Bypass de firma en `jsonwebtoken` (CVE-2015-9235) |
| **Trivy** | Container Security | OS Base (`libc6` / Debian) | **MEDIUM** | Buffer Overflow en `glibc` (CVE-2026-18374)       |
| **OWASP ZAP** | DAST | Runtime (`http://localhost:3000`) | **MEDIUM** | Ausencia de cabecera `Content-Security-Policy`    |

---

## 3. Triage Técnico y Matriz de Remediación

### Hallazgo 1: Inyección SQL en Endpoint de Login (SAST)
* **Herramienta / Regla:** Semgrep (`javascript.sequelize.security.audit.sequelize-injection-express.express-sequelize-injection`)
* **Ubicación:** `src/routes/login.ts:34`
* **Severidad:** High (Semgrep: `ERROR`) / CWE-89 / OWASP A03:2021
* **Triage:** **Verdadero Positivo (Crítico)**. Se identificó una concatenación directa de cadenas provenientes de la petición HTTP (`req.body.email`) dentro del query crudo de Sequelize:
  ```typescript
  // Código Vulnerable
  models.sequelize.query(
    `SELECT * FROM Users WHERE email = '${req.body.email || ''}' AND password = '${security.hash(req.body.password || '')}' AND deletedAt IS NULL`,
    { model: models.User, plain: true }
  )
  ```

**Remediación:** Parametrizar la consulta utilizando _named replacements_ nativos del ORM para forzar el escape contextual:
  ```typescript
  // Fix recomendado
  models.sequelize.query(
    'SELECT * FROM Users WHERE email = :email AND password = :password AND deletedAt IS NULL',
    {
      replacements: { 
        email: req.body.email || '', 
        password: security.hash(req.body.password || '') 
      },
      model: models.User,
      plain: true
    }
  )
  ```

### Hallazgo 2: Exposición de Clave Privada Asimétrica (Secret Scanning)

- **Herramienta:** Trivy (`AsymmetricPrivateKey`) & Semgrep (`generic.secrets`)
- **Ubicación:** `src/lib/insecurity.ts:21` e `infrastructure/terraform/networking.tf:171`
- **Severidad:** High / CWE-798 / OWASP A07:2021
- **Triage:** **Verdadero Positivo (Crítico)**. Se detectaron bloques literales `-----BEGIN RSA PRIVATE KEY-----` en el repositorio utilizados para firmar tokens y certificados TLS
- **Remediación:**
    1. Revocar de inmediato el par de claves expuesto.
    2. Extraer el material criptográfico del código fuente e inyectarlo en tiempo de ejecución mediante un gestor de secretos (ej. AWS Secrets Manager, HashiCorp Vault o GitHub Secrets).

### Hallazgo 3: Bypass Criptográfico en Dependencia Crítica (SCA)

- **Herramienta:** Trivy (`Node.js node-pkg`)
- **Paquete:** `jsonwebtoken` (Versión instalada: `0.1.0` / Versión fixed: `>=4.2.2`)
- **Vulnerabilidad:** `CVE-2015-9235` (CVSS 9.8 / CRITICAL)
- **Triage:** **Verdadero Positivo**. La versión implementada permite a un atacante cambiar el algoritmo en el header a `none` o manipular tokens asimétricos para bypassear la verificación criptográfica y forjar identidades administrativas.
- **Remediación:** Actualizar el paquete en `package.json` a la versión estable actual (`npm install jsonwebtoken@latest`) y fijar algoritmos explícitos en `jwt.verify(token, secret, { algorithms: ['HS256'] })`.

### Hallazgo 4: Ausencia de Cabecera Content Security Policy (DAST)

- **Herramienta:** OWASP ZAP Baseline Scan (Alert ID: `10038`)
- **Objetivo:** `http://localhost:3000` (Sistémico)
- **Severidad:** Medium / CWE-693 / OWASP A05:2021
- **Triage:** **Verdadero Positivo**. El servidor web no entrega la cabecera `Content-Security-Policy`, dejando al navegador sin directivas de restricción ante inyecciones de scripts maliciosos (XSS).
- **Remediación:** Implementar el middleware `helmet` en el arranque de la aplicación Express configurando fuentes confiables:

```typescript
    import helmet from 'helmet'
    
    app.use(
      helmet.contentSecurityPolicy({
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: ["'self'", "'trusted-cdn.com'"],
          objectSrc: ["'none'"],
          upgradeInsecureRequests: [],
        },
      })
    )
```
## 4. Política de Breaking Builds (Quality Gates)
Para evitar la fricción con el equipo de desarrollo, el pipeline implementa una política escalonada de fallos:
- **Bloqueo de Merge (Exit Code 1):** Detección de Secretos hardcodeados (Trivy Secrets) y vulnerabilidades SAST de severidad `ERROR` que involucren inyección directa (SQLi, Command Injection).
- **Alerta sin Bloqueo (Backlog Triage):** Dependencias desactualizadas de severidad `MEDIUM` en el SO base o cabeceras faltantes en DAST, las cuales se canalizan a tickets de remediación programada.