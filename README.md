# **AI Scraping Defense Stack (IIS Version)**

**This system is a work-in-progress and not yet ready for release**

This project provides a multi-layered defense strategy against scraping by unauthorized AI bots, specifically adapted for deployment on **Windows Server using Internet Information Services (IIS)**. It includes real-time detection, tarpitting, honeypots, and behavioral analysis with optional AI/LLM integration.

This version replaces the Nginx/Lua components of the original stack with IIS features and custom ASP.NET Core middleware.

## **Features**

* **IIS Request Filtering (ASP.NET Core Middleware \+ URL Rewrite):** Real-time filtering performed within IIS.  
  * **IP Blocklist Check (Redis \+ C\# Middleware):** A custom ASP.NET Core middleware checks incoming IPs against a Redis blocklist (DB 2\) early in the request pipeline.  
  * **Heuristic Checks (C\# Middleware):** The middleware also performs checks on User-Agents (blocking known bad bots) and request headers.  
  * **Tarpit Redirection (C\# Middleware):** Suspicious requests identified by heuristics are internally rewritten to target the Tarpit API service.  
  * **(Optional) URL Rewrite Rules:** Basic site-wide rules (e.g., forcing HTTPS) can be configured in the root web.config.  
* **IP Blocklisting (Redis \+ AI Service):** Confirmed malicious IPs identified by the Escalation Engine are added to the Redis blocklist (DB 2\) by the AI Service.  
* **Tarpit API (FastAPI \+ PostgreSQL):**  
  * Serves endlessly deep, slow-streaming fake content pages hosted via IIS (HttpPlatformHandler).  
  * Uses **PostgreSQL-backed Markov chains** for persistent and scalable fake text generation.  
  * Generates **deterministic content and links** based on URL hash and system seed.  
  * Implements a **configurable hop limit** tracked per IP in Redis (DB 4), blocking IPs that exceed the limit.  
* **Escalation Engine (FastAPI):** Hosted via IIS (HttpPlatformHandler), processes suspicious requests, applies heuristic scoring (including frequency analysis via Redis DB 3), uses a trained Random Forest model, optionally checks **IP reputation**, and can trigger further analysis (e.g., via local LLM or external APIs). Includes hooks for potential **CAPTCHA challenges**.  
* **AI Service (FastAPI):** Hosted via IIS (HttpPlatformHandler), receives escalation webhooks, manages the Redis blocklist (DB 2), optionally reports blocked IPs to **community blocklists**, and handles configurable alerting (Slack, SMTP, Webhook).  
* **Admin UI (Flask):** Hosted via IIS (HttpPlatformHandler \+ waitress), provides a real-time metrics dashboard.  
* **PostgreSQL Markov Training:** Includes script (rag/train\_markov\_postgres.py) to populate the PostgreSQL Markov database from a text corpus.  
* **Email Entropy Analysis:** Utility script (rag/email\_entropy\_scanner.py) to score email addresses.  
* **JavaScript ZIP Honeypots:** Dynamically generated and rotated ZIP archives (tarpit/rotating\_archive.py).  
* **ML Model Training:** Includes scripts (rag/training.py) to parse logs, label data, extract features, and train a Random Forest classifier.  
* **IIS Deployment:** Designed for deployment directly onto Windows Server with IIS, using web.config files, HttpPlatformHandler, and the ASP.NET Core Module (ANCM).  
* **Secrets Management:** Configuration relies on reading sensitive data (API keys, passwords) from files stored securely on the server, referenced via configuration (appsettings.json, web.config environment variables).

## **Getting Started**

### **See [docs/iis\_deployment\_guide.md](http://docs.google.com/docs/iis_deployment_guide.md) for detailed instructions on deploying this stack using IIS on Windows Server.**

*(Note: The original Docker Compose and Kubernetes deployment methods are not applicable to this IIS-specific version).*

### **Accessing Services (Example IIS Setup)**

Access URLs will depend on your specific IIS site bindings and application aliases. Examples assuming services are hosted under the main site:

* **Main Website / Protected App:** http://your-iis-site.com/ (or https://)  
* **Tarpit Endpoint (Internal):** Accessed via internal rewrite by the C\# middleware (e.g., requests rewritten to /anti-scrape-tarpit/)  
* **Admin UI:** http://your-iis-site.com/admin/ (or /admin/ alias)  
* **(Optional) C\# Middleware Health Check:** http://your-iis-site.com/health (or /filtering/health if hosted as sub-app)

## **Architecture**

See [docs/architecture.md](http://docs.google.com/docs/architecture.md) for a detailed diagram and component overview (ensure this is updated for the IIS architecture).

## **Contributing**

Contributions are welcome\! Please see [CONTRIBUTING.md](http://docs.google.com/CONTRIBUTING.md) for guidelines.

## **License**

This project is licensed under the terms of the GPL-3.0 license. See [LICENSE](http://docs.google.com/LICENSE) for the full text and [license\_summary.md](http://docs.google.com/license_summary.md) for a summary.

## **Security**

Please report any security vulnerabilities according to the policy outlined in [SECURITY.md](http://docs.google.com/SECURITY.md).

## **Ethics & Usage**

This system is intended for defensive purposes only. Use responsibly and ethically. Ensure compliance with relevant laws and regulations in your jurisdiction.
