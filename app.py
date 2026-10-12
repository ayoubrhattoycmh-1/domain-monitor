import re
from concurrent.futures import ThreadPoolExecutor
import pandas as pd
import streamlit as st
import dns.resolver
from streamlit_autorefresh import st_autorefresh

st.set_page_config(page_title="Domain Monitor Free", page_icon="🔎", layout="wide")
st.title("Domain Monitor — 100% Free")
st.caption("Public DNS and email authentication diagnostics. No account, API key or Google authorization required.")

def query(name, typ):
    try:
        r = dns.resolver.Resolver()
        r.timeout = 2
        r.lifetime = 4
        return [str(x).strip('"') for x in r.resolve(name, typ)]
    except Exception:
        return []

def domain_ok(d):
    return len(d) <= 253 and bool(re.fullmatch(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", d))

def get_tags(record):
    return {m.group(1).lower(): m.group(2).strip().lower()
            for m in re.finditer(r"(?:^|;)\s*([a-z]+)\s*=\s*([^;]+)", record, re.I)}

def scan(domain, selector):
    d=domain.strip().lower().rstrip(".")
    if not domain_ok(d):
        return {"Domain":d, "Status":"Invalid domain"}
    a=query(d,"A")
    aaaa=query(d,"AAAA")
    mx=query(d,"MX")
    txt=query(d,"TXT")
    spf=[v for v in txt if v.lower().startswith("v=spf1")]
    dm=[v for v in query("_dmarc."+d,"TXT") if v.lower().startswith("v=dmarc1")]
    tags=get_tags(dm[0]) if len(dm)==1 else {}
    dk="Not checked (selector required)"
    if selector:
        qname=selector+"._domainkey."+d
        dk="Record found" if query(qname,"TXT") or query(qname,"CNAME") else "Record not found"
    warnings=[]
    if not mx: warnings.append("MX missing (if receiving mail)")
    if len(spf)==0: warnings.append("SPF missing")
    if len(spf)>1: warnings.append("Multiple SPF records")
    if len(dm)==0: warnings.append("DMARC missing")
    if len(dm)>1: warnings.append("Multiple DMARC records")
    if len(dm)==1 and tags.get("p") not in ("none","quarantine","reject"):
        warnings.append("DMARC policy invalid/missing")
    if len(dm)==1 and tags.get("p")=="none":
        warnings.append("DMARC monitoring-only policy")
    if selector and dk=="Record not found": warnings.append("DKIM selector DNS not found")
    if not a and not aaaa: warnings.append("No A/AAAA record (may be normal for mail-only domains)")
    return {"Domain":d,"Status":"Checked","A":", ".join(a) or "—",
            "AAAA":", ".join(aaaa) or "—","MX":", ".join(mx) or "—",
            "SPF":spf[0] if len(spf)==1 else ("Missing" if not spf else "Multiple records"),
            "SPF count":len(spf),
            "DMARC":dm[0] if len(dm)==1 else ("Missing" if not dm else "Multiple records"),
            "DMARC policy":tags.get("p","—"),
            "DKIM selector":selector or "—","DKIM DNS":dk,
            "Warnings":"; ".join(warnings) or "No issues detected by these basic checks",
            "Gmail reputation":"Not publicly available"}

def check_dnsbl(ip, zones):
    if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}",ip): return "Not checked"
    octets=ip.split(".")
    if any(int(o)>255 for o in octets): return "Not checked"
    reverse=".".join(reversed(octets))
    results=[]
    for zone in zones:
        if query(reverse+"."+zone,"A"): results.append(zone)
    return ", ".join(results) if results else "No listing detected / DNS access may be restricted"

with st.sidebar:
    st.header("Options")
    selector=st.text_input("DKIM selector (optional)", placeholder="selector1").strip().lower()
    if selector and not re.fullmatch(r"[a-z0-9_-]{1,63}",selector):
        st.error("Invalid DKIM selector")
        st.stop()
    dnsbl=st.checkbox("Optional public DNSBL lookup (website A IP, not necessarily sending IP)",value=False)
    refresh=st.selectbox("Refresh while app is open",["Off","5 minutes","15 minutes","60 minutes"])
    st.caption("DNSBL queries can fail on cloud hosts. Results are not definitive.")
    st.caption("DKIM record presence does not prove DKIM passes on sent messages.")

raw=st.text_area("Enter domains, one per line",height=170,placeholder="example.com\nexample.org")
if st.button("Check domains",type="primary"):
    st.session_state["domains"]=raw
    st.session_state["started"]=True

ms={"Off":0,"5 minutes":300000,"15 minutes":900000,"60 minutes":3600000}[refresh]
if ms and st.session_state.get("started"):
    st_autorefresh(interval=ms,key="refresh")

if st.session_state.get("started"):
    domains=list(dict.fromkeys(x.strip().lower().rstrip(".") for x in st.session_state["domains"].splitlines() if x.strip()))[:100]
    if not domains:
        st.warning("Enter at least one domain.")
    else:
        with st.spinner("Checking public DNS..."):
            with ThreadPoolExecutor(max_workers=8) as pool:
                rows=list(pool.map(lambda d:scan(d,selector),domains))
            if dnsbl:
                for row in rows:
                    ips=[x.strip() for x in row.get("A","").split(",") if x.strip() not in ("","—")]
                    row["A IP DNSBL"]=check_dnsbl(ips[0],["zen.spamhaus.org","bl.spamcop.net"]) if ips else "No A IP"
        df=pd.DataFrame(rows)
        c1,c2,c3=st.columns(3)
        c1.metric("Domains",len(df))
        c2.metric("Valid checked",int((df["Status"]=="Checked").sum()))
        c3.metric("DMARC missing",int((df.get("DMARC",pd.Series(dtype=str))=="Missing").sum()))
        st.dataframe(df,use_container_width=True,hide_index=True)
        st.download_button("Download CSV",df.to_csv(index=False).encode("utf-8-sig"),"domain_monitor.csv","text/csv")
st.info("This app does not estimate Gmail reputation, spam placement, or deliverability. Only Google-authorized sender data can provide Gmail Postmaster reputation.")
