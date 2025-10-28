# Threat Intelligence Dashboard

A web-based dashboard providing real-time threat intelligence by integrating multiple cybersecurity data sources. Check IP address reputation, analyze file hashes, and stay updated with the latest cyber news.

Built with Python (Flask) on the backend and vanilla JavaScript on the frontend, using a "Hacker Terminal" theme. 📟

---

## Features

* **IP Reputation Check:** Enter an IP address to query the **AbuseIPDB API** for its abuse confidence score, country, ISP, and report history.
* **File Hash Analysis:** Enter an MD5, SHA1, or SHA256 hash to query the **VirusTotal API** for malware detection status across multiple antivirus vendors.
* **Latest Cyber News:** Displays the top 20 latest articles from the **KrebsOnSecurity RSS feed**.
* **Unified Interface:** Switch between IP checks, hash checks, and the news feed using intuitive tabs.
* **Themed UI:** Features a "Hacker Terminal" (green screen) aesthetic for a cybersecurity-focused look and feel.

---

## Tech Stack

* **Backend:** Python, Flask
* **Frontend:** HTML, CSS, Vanilla JavaScript
* **APIs:**
    * AbuseIPDB (IP Reputation)
    * VirusTotal (File Hash Analysis)
* **Libraries:**
    * `requests` (for API calls)
    * `feedparser` (for RSS news feed)
    * `python-dotenv` (for environment variables)
* **Server:** Gunicorn (for production)
* **Deployment:** Render

---

## Getting Started

You can run this project locally for development and testing.

### Prerequisites

* Python 3.7+
* An AbuseIPDB API Key (Free)
* A VirusTotal API Key (Free Community Key)

### 1. Clone the Repository

```bash
# Replace with your repository URL
git clone [https://github.com/SSabariGirish/threat-intelligence-dashboard.git](https://github.com/SSabariGirish/threat-intelligence-dashboard.git)
cd threat-intel-dashboard
