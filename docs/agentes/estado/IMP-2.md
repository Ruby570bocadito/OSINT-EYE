# Estado IMP-2 — Interfaz

Actualizado: 2026-10-23 (sesión v2.2, ronda 1)

## Hecho (últimas 24 h)

- Baseline verificada: compileall OK, 118 tests en verde, CLI OK (v2.1.1, a2dba92).
- [x] dashboard-filtros — explorador de hallazgos con búsqueda y filtros por severidad/tipo/módulo:
  endpoint `GET /api/scan/<target>/assets` (agregador tolerante, nunca 500), panel "Findings
  Explorer" 100 % offline vía textContent, cap 200 filas, 10 tests nuevos (suite: 128 en verde).
  Commit a3d61bf. Nota: main está desactualizada (v2.0); trabajo sobre master (HEAD real, v2.1.1).

## En curso

- (IMP-2) dashboard-multiscan — selector de escaneos guardados + vista diff (reusa core/scan_diff.py).

## Bloqueado

- Nada.

## Peticiones a otras zonas

- (IMP-3) core/scan_diff.py: ScanDiff.compare muta self.diff entre llamadas (reuso instanciando por
  comparación); si lo refactorizáis, mantened compare(old, new) -> dict como API.

## Propuestas para el roadmap

- (IMP-2) dashboard-host-detail — panel de detalle al hacer clic en un activo/fila (todas las menciones
  del escaneo a ese activo, cruce entre módulos) — ui/dashboard_template.html
- (IMP-2) wizard-validacion-target — el wizard valida formato de target (dominio/IP/CIDR) con reintentos
  y avisa si parece una URL antes de continuar — ui/wizard.py
