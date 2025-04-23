# **AI Scraping Defense Stack Documentation (IIS Version)**

Welcome to the official documentation for the **AI Scraping Defense Stack (IIS Version)** — a modular system adapted for deployment on Windows Server with IIS, designed for detecting and deterring AI-based web scrapers, bots, and unauthorized data miners.

## **🚀 Overview**

This project includes:

* ✅ IIS-hosted request filtering (ASP.NET Core Middleware \+ URL Rewrite)  
* ✅ IP Blocklisting via Redis  
* ✅ Tarpit API (FastAPI \+ PostgreSQL) hosted via IIS to delay/confuse bots  
* ✅ Escalation engine (FastAPI) for behavioral analysis (heuristics, ML model, optional LLM/API calls) hosted via IIS  
* ✅ AI Service (FastAPI) for blocklist management and alerting hosted via IIS  
* ✅ Admin UI (Flask) with real-time metrics hosted via IIS  
* ✅ Markov-based fake text generation using PostgreSQL  
* ✅ Supporting scripts for training, honeypot generation, etc.

This stack is modular, extensible, and designed for deployment within a Windows Server / IIS environment.

## **📚 Documentation Sections**

### **🧭 Architecture & Setup**

* [System Architecture](http://docs.google.com/architecture.md)  
* [IIS Deployment Guide](http://docs.google.com/iis_deployment_guide.md)

### **💻 API Reference**

* [Endpoint Reference](http://docs.google.com/api_references.md)

### **🛠 Microservice Details**

*(These READMEs describe the Python code and logic within each service folder. For deployment configuration specific to IIS, refer to the [IIS Deployment Guide](http://docs.google.com/iis_deployment_guide.md) and the READMEs within the iis\_configs/ subdirectories).*

* Tarpit Service Logic: [tarpit/README.md](http://docs.google.com/tarpit/README.md) *(Review recommended)*  
* Escalation Engine Logic: [escalation/README.md](http://docs.google.com/escalation/README.md)  
* AI Service Logic: [ai\_service/README.md](http://docs.google.com/ai_service/README.md)  
* Admin UI Logic: [admin\_ui/README.md](http://docs.google.com/admin_ui/README.md)

## **⚖️ Legal & Compliance**

* [License Summary](http://docs.google.com/license_summary.md)  
* [Third-Party Licenses](http://docs.google.com/third_party_licenses.md)  
* [Security Disclosure Policy](http://docs.google.com/SECURITY.md)

## **🤝 Contributing**

* [How to Contribute](http://docs.google.com/CONTRIBUTING.md)  
* [Changelog](http://docs.google.com/CHANGELOG.md)  
* [Code of Conduct](http://docs.google.com/code_of_conduct.md)

## **📦 Deployment**

Deployment for this version is handled directly on Windows Server using IIS.

### **See the [IIS Deployment Guide](http://docs.google.com/iis_deployment_guide.md) for detailed instructions.**

## **🔗 System Components**

* C\# ASP.NET Core Filtering Middleware  
* Tarpit API (FastAPI)  
* Escalation Engine (FastAPI)  
* AI Service (FastAPI)  
* Admin UI (Flask)  
* Supporting Python Modules & Scripts

📈 Monitoring  
Access the Admin UI via the alias configured during IIS setup (e.g., http://your-site/admin/).  
💡 Learn More  
Explore the source code repository for further details.  
📢 Feedback & Security  
To report bugs or vulnerabilities, refer to the Security Policy.