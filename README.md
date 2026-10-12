# Domain Monitor Free

100% free Streamlit dashboard. No Google Postmaster authorization, API key, or paid subscription.

## GitHub update
Replace `app.py` and `requirements.txt` in your repository root, add `README.md`, then Commit changes. Streamlit Community Cloud redeploys from the branch automatically.

## Checks
A, AAAA, MX, SPF (including duplicate detection), DMARC policy, optional DKIM selector DNS lookup, configuration warnings, CSV export, optional public DNSBL lookup, and session auto-refresh.

## Important limitations
- Gmail reputation is private and cannot be determined from public DNS.
- DKIM requires a known selector. DNS record presence is not message authentication validation.
- A record IP is usually NOT the outgoing email server IP; DNSBL results are only about that queried IP.
- Public DNSBL providers may restrict DNS queries from Streamlit Cloud or require commercial access for some usage. Disable optional DNSBL if results are unreliable.
- DNS checks do not prove inbox placement or actual SPF/DKIM/DMARC pass.
