# Challenge rubric mapping

| Rubric item | Implementation surface | Verifiable behavior |
| --- | --- | --- |
| Brand profile (15%) | `frontend/src/brands.tsx`, `/api/brands`, `backend/src/brands.ts` | Persists names, domain, alternate names, keywords, publisher and official assets in PostgreSQL. |
| Social monitoring (30%) | `backend/src/social.ts`, Reddit and YouTube adapters, `backend/src/monitoring.ts` | Searches public discussions/videos; stores matching context, account/channel URL, name/content signals and exact verified exclusions. |
| App Store monitoring (30%) | `backend/src/app-stores.ts` | Uses Apple public Search API results; compares names, descriptions and supplied publisher identity; excludes exact official store IDs/URLs. |
| Logo and look-alike bonus | `backend/src/logo-similarity.service.ts`, `backend/src/lookalike.service.ts` | Computes image similarity from decoded pixels and normalized name similarity; an image failure remains unassessed. |
| User experience (15%) | React dashboard and source-status cards | Shows loading/error/empty states, evidence and excluded assets. Unconfigured/rate-limited sources are not represented as successful clean checks. |
| Architecture/demo deliverable (10%) | `docs/architecture.md`, `docs/data-sources.md`, `docs/demo-script.md` | Diagram, limitations, source configuration, and reproducible demonstration steps. |

The service makes no claim to enumerate private or all social accounts, determine account compromise without authorized provider data, establish malicious intent from one match, or submit platform takedowns.
