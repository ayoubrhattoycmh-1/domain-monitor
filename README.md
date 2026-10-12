# Domain DNS & Email Authentication Monitor

Enter domain names, one per line. Checks public A, MX, SPF and DMARC records, and exports CSV.

## Run on Windows

1. Install Python 3.10+.
2. Open a terminal in this folder.
3. Run `pip install -r requirements.txt`.
4. Run `streamlit run app.py`.

This does **not** measure Gmail domain/IP reputation, spam complaints or inbox placement. Google Postmaster Tools requires verified domain ownership and authorized access; its metrics are not real-time. DKIM validation needs a selector or actual email headers.
