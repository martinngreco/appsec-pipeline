# DevSecOps & AppSec CI/CD Pipeline Lab

Pipeline automatizado de seguridad implementado sobre OWASP Juice Shop para validar detección estática, de dependencias y dinámica en entornos CI/CD.

## Arquitectura del Pipeline
* **SAST (Static Application Security Testing):** Semgrep OSS configurado con reglas comunitarias automáticas para identificar patrones inseguros de código (SQLi, XSS, deserialización insegura).
* **SCA & Container Scanning:** Trivy ejecutando análisis en dos capas: árbol de dependencias (`package-lock.json`) e inspección de capas/SO de la imagen Docker.
* **DAST (Dynamic Application Security Testing):** OWASP ZAP Baseline Scanner ejecutado contra el contenedor en ejecución en el runner para detectar cabeceras faltantes, cookies inseguras y endpoints expuestos.

## Análisis y Triage de Hallazgos

### 1. Hallazgo SAST: Inyección SQL en endpoint de autenticación
* **Herramienta:** Semgrep
* **Ubicación:** `routes/login.js`
* **Vulnerabilidad:** Concatenación directa de strings en consultas Sequelize (`models.sequelize.query(...)`).
* **Severidad:** Crítica
* **Triage:** **Verdadero Positivo**.
* **Remediación:** Parametrizar la consulta utilizando *prepared statements* o el mapeo nativo del ORM:
  ```javascript
  // Fix recomendado
  models.sequelize.query('SELECT * FROM Users WHERE email = :email AND password = :password', 
    { replacements: { email: req.body.email, password: security.hash(req.body.password) } }
  );