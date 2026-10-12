import re
import time
from datetime import date, timedelta
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import streamlit as st
import dns.resolver
import requests
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="Domain Monitor Pro", page_icon="📬", layout="wide")
st.title("Domain DNS & Email Health Monitor")
st.caption("Public DNS diagnostics, optional blocklist checks and authorized Google Postmaster statistics. DNS health is NOT Gmail reputation.")

def lookup(name, kind, timeout=3):
    try:
        ans = dns.resolver.resolve(name, kind, lifetime=timeout)
        return [str(x).strip('"') for x in ans]
    except Exception:
        return []

def valid_domain(d):
    return bool(len(d) <= 253 and re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", d))

def policy(record):
    m = re.search(r"(?:^|;)\s*p\s*=\s*(none|quarantine|reject)\b", record, re.I)
    return m.group(1).lower() if m else "Unclear"

def dnsbl(ip, zones):
    try:
        parts = ip.split(".")
        if len(parts) != 4 or any(not x.isdigit() or not 0 <= int(x) <= 255 for x in parts):
            return "Not checked"
        reverse = ".".join(reversed(parts))
        listed = [zone for zone in zones if lookup(reverse + "." + zone, "A", 2)]
        return ", ".join(listed) if listed else "No listing found (selected lists)"
    except Exception:
        return "Check unavailable"

def check(domain, selector, blocklists):
    domain = domain.lower().strip().rstrip(".")
    if not valid_domain(domain):
        return {"Domain": domain, "Status": "Invalid domain", "Health score": None}
    a = lookup(domain, "A")
    mx = lookup(domain, "MX")
    txt = lookup(domain, "TXT")
    spfs = [x for x in txt if x.lower().startswith("v=spf1")]
    dmarcs = [x for x in lookup("_dmarc." + domain, "TXT") if x.lower().startswith("v=dmarc1")]
    dkims = [x for x in lookup(selector + "._domainkey." + domain, "TXT") if "v=dkim1" in x.lower() or "p=" in x.lower()] if selector else []
    dkim_cname = lookup(selector + "._domainkey." + domain, "CNAME") if selector else []
    dmarc_policy = policy(dmarcs[0]) if dmarcs else "Missing"
    # Diagnostic score only: not deliverability, not Gmail reputation.
    score = (20 if a else 0) + (20 if mx else 0) + (25 if len(spfs) == 1 else 0) + (25 if len(dmarcs) == 1 and dmarc_policy != "Unclear" else 0)
    if selector:
        score += 10 if dkims or dkim_cname else 0
    else:
        score += 10 if dmarcs and dmarc_policy in ("quarantine", "reject") else 0
    return {
        "Domain": domain, "Status": "Checked", "Health score": score,
        "A": ", ".join(a) or "Missing", "MX": ", ".join(mx) or "Missing",
        "SPF": spfs[0] if spfs else "Missing",
        "SPF records": len(spfs),
        "DMARC policy": dmarc_policy,
        "DMARC record": dmarcs[0] if dmarcs else "Missing",
        "DKIM selector": selector or "Not provided",
        "DKIM DNS": ("Found" if dkims or dkim_cname else "Not found") if selector else "Not checked",
        "Selected DNSBLs": dnsbl(a[0], blocklists) if a and blocklists else "Not checked",
        "Gmail reputation": "Requires verified Google Postmaster access",
    }

def postmaster(domain):
    """Optional Google Postmaster Tools API. Only verified, authorized domains."""
    try:
        cfg = st.secrets.get("postmaster", {})
        cid, secret, refresh = cfg.get("client_id"), cfg.get("client_secret"), cfg.get("refresh_token")
        if not all((cid, secret, refresh)):
            return "Not connected", "Not connected", "Not connected"
        token_response = requests.post("https://oauth2.googleapis.com/token",
            data={"client_id": cid, "client_secret": secret, "refresh_token": refresh, "grant_type": "refresh_token"}, timeout=10)
        token_response.raise_for_status()
        token = token_response.json()["access_token"]
        headers = {"Authorization": "Bearer " + token}
        # Recent dates may be delayed; try the last 7 completed days.
        for days_ago in range(1, 8):
            d = (date.today() - timedelta(days=days_ago)).isoformat()
            url = f"https://gmailpostmastertools.googleapis.com/v1/domains/{domain}/trafficStats/{d}"
            r = requests.get(url, headers=headers, timeout=10)
            if r.status_code == 404:
                continue
            if r.status_code in (401, 403):
                return "Not authorized", "Not authorized", "Not authorized"
            r.raise_for_status()
            data = r.json()
            return data.get("domainReputation", "No data"), data.get("userReportedSpamRatio", "No data"), d
        return "No recent data", "No recent data", "—"
    except Exception:
        return "API unavailable", "API unavailable", "—"

with st.sidebar:
    st.header("Settings")
    selector = st.text_input("DKIM selector (optional)", placeholder="selector1").strip()
    use_dnsbl = st.checkbox("Check public DNS blocklists (A record IP only)", value=False)
    zones = ["zen.spamhaus.org", "bl.spamcop.net"] if use_dnsbl else []
    use_postmaster = st.checkbox("Check authorized Google Postmaster data", value=False)
    refresh = st.selectbox("Auto-refresh", ["Off", "5 minutes", "15 minutes", "60 minutes"])
    st.caption("DNSBL checks may be restricted by hosting provider DNS. A-record IP is not necessarily your sending IP.")
    st.caption("DKIM DNS existence does not prove signed messages pass authentication.")

raw = st.text_area("Domains (one per line)", value=st.session_state.get("domains", ""), height=160,
                   placeholder="example.com\nexample.org")
run = st.button("Check domains", type="primary")
if run:
    st.session_state["domains"] = raw
    st.session_state["checked"] = True

intervals = {"Off": 0, "5 minutes": 300000, "15 minutes": 900000, "60 minutes": 3600000}
if intervals[refresh] and st.session_state.get("checked"):
    st_autorefresh(interval=intervals[refresh], key="domain_refresh")

if st.session_state.get("checked"):
    domains = list(dict.fromkeys(x.strip().lower().rstrip(".") for x in st.session_state["domains"].splitlines() if x.strip()))[:100]
    if not domains:
        st.warning("Enter at least one domain.")
    else:
        with st.spinner("Checking domains..."):
            with ThreadPoolExecutor(max_workers=8) as pool:
                rows = list(pool.map(lambda d: check(d, selector, zones), domains))
            if use_postmaster:
                for row in rows:
                    if row["Status"] == "Checked":
                        rep, spam, asof = postmaster(row["Domain"])
                        row["Gmail reputation"] = rep
                        row["Gmail spam ratio"] = spam
                        row["Postmaster data date"] = asof
        df = pd.DataFrame(rows)
        checked = df[df["Status"] == "Checked"]
        a,b,c = st.columns(3)
        a.metric("Domains checked", len(checked))
        b.metric("Average DNS health", f'{checked["Health score"].mean():.0f}/100' if len(checked) else "—")
        c.metric("DMARC missing", int((checked["DMARC policy"] == "Missing").sum()) if len(checked) else 0)
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button("Download CSV", df.to_csv(index=False).encode(), "domain_monitor_results.csv", "text/csv")
        st.caption("Health score is an illustrative DNS configuration score, not an inbox-placement or reputation prediction.")
st.info("Gmail domain reputation is not public or real-time. For verified domains, configure Google Postmaster OAuth credentials in Streamlit Secrets.")
