# Domain Monitor v2

Streamlit dashboard for public DNS/email configuration checks. Upload `app.py`, `requirements.txt`, and `README.md` to the ROOT of your GitHub repository, then deploy `app.py` on Streamlit Community Cloud.

Features: A/MX/SPF/DMARC checks; optional DKIM selector DNS lookup; illustrative 0–100 DNS health score; optional public DNSBL checks against A-record IP (NOT necessarily sending IP); CSV export; automatic refresh while app is open; optional authorized Google Postmaster API.

## Google Postmaster (optional)
Google Postmaster Tools requires verified domains, permission, and OAuth access. Google Postmaster data is delayed and may be unavailable for low-volume domains. Obtain a refresh token with `https://www.googleapis.com/auth/postmaster.readonly` scope and configure **Streamlit App Settings → Secrets**, never commit credentials to GitHub:

```toml
[postmaster]
client_id = "YOUR_OAUTH_CLIENT_ID"
client_secret = "YOUR_OAUTH_CLIENT_SECRET"
refresh_token = "YOUR_OAUTH_REFRESH_TOKEN"
```

If Google access is absent, leave the Postmaster option off. Domain reputation is never inferred from DNS checks.

## Notes
- A/MX/SPF/DMARC DNS presence does not prove message authentication pass or inbox placement.
- DKIM selector is optional and must be supplied to check DKIM DNS.
- DNSBL lookups can be blocked by cloud-hosted resolvers; no listing found is not proof of clean IP reputation.
- Auto-refresh works only while the Streamlit session is active.
- This app never sends emails.
