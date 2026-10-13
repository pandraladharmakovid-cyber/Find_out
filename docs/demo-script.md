# Short demo (4–5 minutes)

## 1. Register a brand

1. Open **Brand profiles** and create an organization-owned brand name and primary domain.
2. Add an official social account, the exact mobile-app bundle/store ID and URL, its publisher name, and an official logo by HTTPS URL or PNG/JPEG/WebP upload (up to 2 MB).
3. Show that the asset registry is stored by the API and remains after refresh.

## 2. Run social and app monitoring

1. Select the brand under **Social & App Monitoring** and start a scan.
2. Show per-source availability. Reddit and YouTube require credentials; Apple App Store search uses its public API. If a source is unavailable, point out the explicit unavailable status rather than treating the zero results as clean.
3. Review listings with name, publisher, description, and (when configured and retrievable) actual icon/logo similarity evidence.
4. Confirm an exact registered social ID/app ID or store URL is marked **Official asset excluded** and has zero assigned risk.

## 3. Investigate and respond

1. Open a candidate source URL in **Investigations** and review the available URLhaus/Safe Browsing checks and evidence.
2. In **Recovery**, choose “entered a password” and show the tailored steps. The result says **unverified** because no provider/device access was queried.
3. Save an internal report and show its reference/status. Explain that this records a report for review; it does not submit a platform takedown.

## Deterministic checks

`npm test` includes controlled unit fixtures for official-asset exclusion, a real iTunes response normalization path, source failure status, and actual image-pixel similarity. Those fixtures verify code behavior only; they are not presented as live detections.
