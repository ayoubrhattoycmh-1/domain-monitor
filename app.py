import streamlit as st
import dns.resolver
import pandas as pd
from concurrent.futures import ThreadPoolExecutor

st.set_page_config(page_title='Domain DNS Monitor', layout='wide')
st.title('Domain DNS & Email Authentication Monitor')
st.caption('Public DNS checks only. Gmail reputation and inbox placement cannot be determined from a domain name alone.')

def query(name, record_type):
    try:
        return [str(r).strip('"') for r in dns.resolver.resolve(name, record_type, lifetime=4)]
    except Exception:
        return []

def check(domain):
    domain = domain.strip().lower().rstrip('.')
    if not domain or ' ' in domain or '/' in domain or len(domain)>253 or '.' not in domain:
        return {'Domain': domain, 'Status': 'Invalid'}
    txt = query(domain, 'TXT')
    spf = [t for t in txt if t.lower().startswith('v=spf1')]
    dmarc = [t for t in query('_dmarc.'+domain, 'TXT') if t.lower().startswith('v=dmarc1')]
    mx = query(domain, 'MX')
    a = query(domain, 'A')
    policy = 'Missing'
    if dmarc:
        import re
        match = re.search(r'(?:^|;)\s*p\s*=\s*(none|quarantine|reject)', dmarc[0], re.I)
        policy = match.group(1).lower() if match else 'Unclear'
    return {'Domain': domain, 'Status': 'Checked', 'A': ', '.join(a) or 'Missing', 'MX': ', '.join(mx) or 'Missing', 'SPF': spf[0] if spf else 'Missing', 'DMARC policy': policy, 'DMARC record': dmarc[0] if dmarc else 'Missing', 'Gmail reputation': 'Not publicly available'}

raw = st.text_area('Domains (one per line)', placeholder='example.com\nexample.org', height=160)
if st.button('Check domains', type='primary'):
    domains = list(dict.fromkeys(line.strip() for line in raw.splitlines() if line.strip()))[:100]
    if not domains:
        st.warning('Enter at least one domain.')
    else:
        with st.spinner('Checking public DNS records...'):
            with ThreadPoolExecutor(max_workers=10) as pool:
                rows = list(pool.map(check, domains))
        df = pd.DataFrame(rows)
        st.dataframe(df, use_container_width=True, hide_index=True)
        st.download_button('Download CSV', df.to_csv(index=False).encode('utf-8'), 'domain_checks.csv', 'text/csv')
st.info('DKIM needs a known selector and is not checked here. DNS records alone do not prove that email authentication passes for a sent message.')
