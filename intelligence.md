THIS SAVES ALL THE LATEST CHANGES BEING MADE TO THE BACKEND

# Security Intelligence Engine
## Scout Report Generator

> This document is the source-of-truth specification for the Security Intelligence system.
>
> Before modifying `intelligence.js`, `index.js`, or the Intelligence frontend, review this document first.
>
> The intelligence system is designed to provide meaningful security observations and analysis.
> It is READ-ONLY and must NOT perform remediation, modify alerts, assign alerts, close alerts,
> change risk status, or take security actions.

---

# 1. PURPOSE

The Security Intelligence Engine analyzes daily security reports stored in the backend database.

Its purpose is to answer questions such as:

- What is happening in the latest security report?
- Has alert volume increased or decreased?
- Which alert sources are driving the change?
- Which alerts are new?
- Which alerts have carried over?
- Which alerts have persisted for multiple reports?
- Are high-risk alerts remaining unresolved?
- Are alerts unassigned?
- Is activity concentrated around a particular channel?
- Is activity concentrated around a particular policy?
- Which alerts deserve attention first?
- What meaningful patterns are emerging over time?

The engine should provide:

1. Deterministic metrics
2. Explainable findings
3. Historical comparison
4. Alert lifecycle analysis
5. Alert persistence / aging analysis
6. Alert prioritization
7. Security-pattern detection

The engine must NOT make security changes.

---

# 2. BACKEND ARCHITECTURE

The backend runs on Cloudflare Workers.

Main backend entry point:

`index.js`

Security intelligence implementation:

`intelligence/intelligence.js`

Frontend:

`intelligence.html`
`intelligence.js`

API:

`GET /api/v1/intelligence/summary`

---

# 3. INTELLIGENCE API

## Endpoint

GET:

`/api/v1/intelligence/summary`

Full endpoint:

`https://dailyreportgenbackend.adityakumarsahu108.workers.dev/api/v1/intelligence/summary`

There is NO report ID parameter.

The intelligence API automatically determines the latest report and previous report from the database.

---

# 4. API RESPONSE

The API returns:

```json
{
  "success": true,
  "data": {
    "generatedAt": "...",

    "report": {},

    "alerts": {},

    "comparison": {},

    "lifecycle": {},

    "aging": {},

    "securityIntelligence": {},

    "prioritization": {},

    "insights": []
  }
}


### How we'll use it next time

Instead of pasting that massive `intelligence.js`, you can tell Claude:

> **"Read `INTELLIGENCE.md` and the current `intelligence.js`. I want to add re-emerging alert detection. Keep the existing API contract and make the feature read-only."**

That gives Claude the **architecture + rules + existing capabilities + roadmap** in one place.

One important thing: **keep the actual `intelligence.js` alongside this MD**. The MD is the specification/blueprint; it isn't a replacement for the source code.