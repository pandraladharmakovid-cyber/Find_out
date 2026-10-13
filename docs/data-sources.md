# Data sources, coverage, and limitations

| Source | Data collected | Configuration | Failure behavior |
| --- | --- | --- | --- |
| Reddit OAuth search | Public discussion posts, author, permalink, text context | `REDDIT_CLIENT_ID`, `REDDIT_CLIENT_SECRET`, `REDDIT_USER_AGENT` | Missing credentials, rate limits, and network failures are reported as unavailable; no findings are inferred from a skipped request. |
| YouTube Data API v3 | Public video titles, descriptions, channel names/IDs, and video URLs | `YOUTUBE_API_KEY` | Quota, API, and network failures are reported as unavailable. This is video/channel search, not a global account crawl. |
| Apple App Store Search API | Public software listing names, bundle IDs, seller, description, icon URL, and listing URL | Public search endpoint; no API key | HTTP and timeout failures appear as unavailable. Search results are not exhaustive app-store inventory. |
| Google Safe Browsing | URL reputation matches | `GOOGLE_SAFE_BROWSING_API_KEY` | When not configured or unavailable, source evidence has no verification; it is not considered a clean result. |
| URLhaus | URL threat-intelligence lookup | `URLHAUS_AUTH_KEY` when required by the source | Failure is recorded in investigation evidence/audit status; it is not a clean result. |
| Gemini explanation | Evidence summarization only | `GEMINI_API_KEY` | Optional; rule-based evidence remains available. Generated explanations must not replace source evidence. |

## Detection and exclusion

- Name comparison uses normalized Unicode text, similarity, and match context. A single similar name does not establish abuse.
- App risk uses name similarity, registered-publisher mismatch (when supplied), and brand references in the listing description.
- Social results are public posts/videos with associated account/channel context. Keyword indicators are triage signals, not proof of impersonation.
- Only verified registry entries are eligible for exclusion. Social identifiers and app bundle IDs/store URLs are exact-match exclusions; publisher name alone is not enough to mark an app official.
- App icons are compared to registered HTTPS logo images or uploaded PNG/JPEG/WebP logos (up to 2 MB) for the top three name-matching listings using an 8×8 grayscale average hash. Remote image downloads reject redirects, private/reserved IPs, non-images, and payloads larger than 2 MB. A failed or unconfigured comparison remains `Not assessed`; it is not synthesized from image URLs.
- The prototype does not crawl private pages, bypass platform access controls, submit takedown requests, or report verified victim counts.

Configure keys in `backend/.env` (copy `backend/.env.example`). Do not place source credentials in frontend configuration.
