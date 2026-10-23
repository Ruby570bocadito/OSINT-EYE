# Claim: scan-diff-stateless

- **Agente:** IMP-3
- **Fecha/hora UTC:** 2026-10-23 17:25 UTC
- **Tarea (Petición IMP-2 en estado/IMP-2.md):** core/scan_diff.py — ScanDiff.compare() muta self.diff entre llamadas (new_ports/new_cves/new_cloud_buckets acumulan con append); hacerlo reutilizable reseteando el esqueleto al inicio de compare()
- **Rutas que voy a tocar:**
  - `core/scan_diff.py` (reset del esqueleto en compare(); sin cambio de API)
  - `tests/test_core_scan_diff.py` (nuevo, tests offline de reutilización)
- **Verificación previa:** reproducido por lectura: _diff_ports/_diff_cves/_diff_cloud hacen append sobre self.diff; consumidores actuales (dashboard, osint_eye) instancian por llamada, pero la reutilización duplica entradas; claims activos sin solape.
