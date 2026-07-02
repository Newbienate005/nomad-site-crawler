import time
from urllib.parse import urljoin, urlparse
import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup

# --- STREAMLIT UI CONFIGURATION ---
st.set_page_config(page_title="Nomad Vulnerability Scanner", page_icon="🛡️")
st.title("🛡️ Nomad Vulnerability & Site Crawler")
st.write(
    "Enter your company website below to run a security header check, discover broken links, and audit sensitive paths."
)

# User Inputs
target_url = st.text_input("Target URL:", "https://wknd.nomad.africa/")
start_scan = st.button("Launch Scan 🚀")

# Sensitive paths to check
SENSITIVE_PATHS = [
    ".env",
    ".git/",
    "wp-config.php",
    "config.json",
    "admin/",
    "backup.zip",
    "robots.txt",
]


# --- SCANNING LOGIC ---
def run_vulnerability_scan(start_url):
    domain = urlparse(start_url).netloc
    visited_urls = set()
    urls_to_visit = [start_url]

    # Data collections for the UI tables
    header_issues = []
    exposed_paths = []
    broken_links = []

    log_placeholder = st.empty()
    status_text = st.sidebar.empty()

    # 1. Quick Check for Exposed Files
    status_text.info("Scanning for exposed paths...")
    for path in SENSITIVE_PATHS:
        test_url = urljoin(start_url, path)
        try:
            res = requests.get(
                test_url,
                headers={"User-Agent": "NomadScannerUI/1.0"},
                timeout=5,
            )
            if res.status_code == 200:
                exposed_paths.append({"Exposed URL": test_url, "Status": 200})
        except:
            pass
        time.sleep(0.2)

    # 2. Main Crawl Loop
    status_text.info("Crawling site structure...")
    while urls_to_visit and len(visited_urls) < 20:  # Cap at 20 for UI demo speed
        current_url = urls_to_visit.pop(0)
        if current_url in visited_urls:
            continue

        log_placeholder.text(f"Scanning page: {current_url}")

        try:
            res = requests.get(
                current_url,
                headers={"User-Agent": "NomadScannerUI/1.0"},
                timeout=5,
            )
            visited_urls.add(current_url)

            # Check Headers
            important_headers = [
                "Content-Security-Policy",
                "X-Frame-Options",
                "X-Content-Type-Options",
            ]
            missing = [h for h in important_headers if h not in res.headers]
            if missing:
                header_issues.append(
                    {"URL": current_url, "Missing Headers": ", ".join(missing)}
                )

            # Check Integrity
            if res.status_code >= 400:
                broken_links.append(
                    {"URL": current_url, "Status Code": res.status_code}
                )
                continue

            # Find next links
            soup = BeautifulSoup(res.text, "html.parser")
            for link in soup.find_all("a", href=True):
                full_url = urljoin(current_url, link["href"])
                parsed_url = urlparse(full_url)
                if parsed_url.netloc == domain:
                    clean_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
                    if (
                        clean_url not in visited_urls
                        and clean_url not in urls_to_visit
                    ):
                        urls_to_visit.append(clean_url)
        except:
            pass
        time.sleep(0.5)

    status_text.success("Scan Finished!")
    log_placeholder.empty()
    return header_issues, exposed_paths, broken_links


# --- TRIGGER SCAN AND DISPLAY RESULTS ---
if start_scan:
    if not target_url.startswith("http"):
        st.error("Please enter a valid URL starting with http:// or https://")
    else:
        headers_data, paths_data, broken_data = run_vulnerability_scan(
            target_url
        )

        st.subheader("📊 Scan Results Summary")

        # Display Exposed Paths Layout
        st.write("### 🚨 Exposed Paths / Files")
        if paths_data:
            st.dataframe(pd.DataFrame(paths_data), use_container_width=True)
        else:
            st.success("No sensitive configuration paths were found open!")

        # Display Missing Security Headers
        st.write("### ⚠️ Missing Security Headers")
        if headers_data:
            st.dataframe(pd.DataFrame(headers_data), use_container_width=True)
        else:
            st.success("All audited pages have ideal security headers.")

        # Display Broken Links
        st.write("### ❌ Broken Links (404/500 errors)")
        if broken_data:
            st.dataframe(pd.DataFrame(broken_data), use_container_width=True)
        else:
            st.success("No broken links found during the crawl.")