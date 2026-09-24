# UI Canonicalization Decision

Status: first-pass decision candidate. No frontend was deleted or migrated.

## Compared implementations

| UI | Location | Runtime | Evidence of scope | API usage | Test/documentation evidence |
|---|---|---|---|---|---|
| Root TRAPSIG console | `src/app`, `src/components/ids` | Next.js 16 / React 19 | Overview, honeypots, live events, sessions, detections, models, experiments, mode/demo/live workflows, Pi controls | Root `/api/ids/*` facade; adapter forwards live/control calls to FastAPI | Root tests cover auth forwarding and mode coherence; inner tests reference root route behavior |
| Inner companion dashboard | `iot-honeypot-ids/dashboard/frontend` | Vite 5 / React 18 | Overview, sessions, detections, models, experiments, replay; Kibana/API links | Direct `VITE_API_URL` calls to FastAPI | No frontend test suite found in inspected package; README describes it as lightweight companion |

## Candidate decision

The root Next.js console is the canonical UI candidate because it has the broader TRAPSIG user-facing surface and the active regression tests for mode semantics and server-side API-key forwarding. The inner Vite app is not equivalent: its source explicitly describes it as a lightweight companion and its implemented navigation omits honeypots, live events, campaigns, and the root mode/demo controls.

This is a migration decision, not a deletion authorization. The root app must retain the required SOC/research functions while its API facade is consolidated around FastAPI.

## Target UI boundary

```text
Browser
  -> Next.js UI
  -> explicit server-side facade/proxy where needed
  -> FastAPI canonical API
  -> Elasticsearch / runtime ML / Pi control plane
```

The browser must continue to receive backend-owned mode, status, lineage, and error states. It must not synthesize live telemetry or silently fall back to demo data when FastAPI or Elasticsearch is unavailable.

## Migration work required

1. Map every root `/api/ids/*` route to a FastAPI route or mark it as UI-only presentation behavior.
2. Preserve root tests before changing route implementations.
3. Compare any unique Vite replay or API behaviors against the root UI and FastAPI contract.
4. Update deployment/docs so only the selected UI is described as production-facing.
5. Archive the Vite app only after no active consumer remains and the deletion inventory is approved.

## Not selected

The Vite app is not selected as the production dashboard because it currently exposes a smaller feature set and has no comparable evidence of the root UI's mode/lineage/control-plane coverage.
