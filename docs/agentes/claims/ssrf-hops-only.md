# Claim: ssrf-hops-only

- **Agente:** SEG
- **Fecha/hora UTC:** 2026-10-23 16:30 UTC
- **Tarea:** refinamiento de ssrf-redirects detectado por TEST: `safe_get` validaba también la URL inicial, lo que rompía el escaneo legítimo de targets locales (`python osint_eye.py localhost --modules web` devolvía 0 tecnologías; el e2e contra fixtures loopback del ROADMAP quedaba imposible). El objetivo inicial es elección explícita del operador (como nmap/httpx); la validación SSRF aplica a los hops de redirección, que es lo que la tarea ROADMAP pide.
- **Rutas que voy a tocar:**
  - `modules/web/ssrf_guard.py` (mover la validación tras cada hop)
  - `tests/test_seg_ssrf_guard.py` (tests ajustados + 3 nuevos; FakeResponse con elapsed/cookies)
- **Verificación previa:** sin claims activos sobre modules/web/ (IMP-1 tiene http-client-unico reclamado pero sin push todavía; mis rutas no colisionan con modules/_http.py).
