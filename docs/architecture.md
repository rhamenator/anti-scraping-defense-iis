# **System Architecture (IIS Version)**

This document provides a high-level overview of how the components in the IIS-adapted AI Scraping Defense Stack interact.

## **🧱 Component Overview & Data Flow**

The system employs a layered approach within an IIS hosting environment:

1. **Edge Filtering (IIS \+ ASP.NET Core Middleware):** Incoming requests first hit IIS.  
   * **C\# Middleware (RedisBlocklistMiddlewareApp):** This ASP.NET Core application, hosted via the ASP.NET Core Module (ANCM) in IIS, runs early in the request pipeline.  
     * It checks the incoming IP against the Redis blocklist (DB 2). Blocked IPs get a 403 response immediately.  
     * It performs heuristic checks based on User-Agent (blocking known bad bots) and request headers.  
     * Suspicious requests identified by heuristics have their path internally rewritten to target the Tarpit API application path.  
   * **IIS URL Rewrite (Optional):** Basic site-wide rules (like forcing HTTPS) can be applied in the root web.config.  
   * Requests passing the middleware checks (and not rewritten) are routed by IIS to the appropriate backend application (e.g., Admin UI, or the real protected application).  
2. **Tarpit & Escalation:**  
   * **Tarpit API (FastAPI):** Hosted via IIS (HttpPlatformHandler), receives requests rewritten by the C\# middleware or potentially directly if routing allows.  
     * Logs the hit and flags the IP visit (Redis DB 1).  
     * Checks a hop counter for the IP (Redis DB 4). If the configured limit (TAR\_PIT\_MAX\_HOPS) is exceeded, it triggers an immediate block by adding the IP to Redis DB 2 and returns a 403\.  
     * If the limit is not exceeded, it sends request metadata to the Escalation Engine.  
     * Generates deterministic fake page content (using Markov chains from PostgreSQL) and links.  
     * Streams the fake page slowly back to the client.  
   * **Escalation Engine (FastAPI):** Hosted via IIS (HttpPlatformHandler), analyzes metadata from the Tarpit API.  
     * Performs frequency analysis using Redis DB 3\.  
     * Applies heuristic scoring and runs a pre-trained Random Forest model.  
     * Optionally calls external IP reputation services or local/external classification APIs (e.g., LLMs).  
     * If the request is deemed malicious, it forwards details to the AI Service.  
3. **AI Service & Actions:**  
   * **AI Service (FastAPI):** Hosted via IIS (HttpPlatformHandler), receives confirmed malicious request data.  
     * Adds the offending IP address to the Redis blocklist (DB 2\) with a configurable TTL.  
     * Optionally reports the IP to configured community blocklists.  
     * Dispatches alerts via configured methods (Slack, SMTP, Webhook).  
4. **Backend Python Services (Hosting):**  
   * **FastAPI Services (Tarpit, Escalation, AI Service):** Run using an ASGI server like uvicorn, managed by IIS via HttpPlatformHandler.  
   * **Flask Service (Admin UI):** Runs using a WSGI server like waitress, managed by IIS via HttpPlatformHandler.  
5. **Monitoring & Background Tasks:**  
   * **Admin UI (Flask):** Fetches real-time metrics from the shared metrics.py module.  
   * **Archive Rotator:** Background Python script (rotating\_archive.py) periodically generates new JS ZIP honeypots. Typically run via Windows Task Scheduler in this environment.  
   * **Training Scripts:** Offline scripts (rag/training.py, rag/train\_markov\_postgres.py) use logs and other data to train the ML model and populate the PostgreSQL Markov database. Run manually or via Task Scheduler.

### **Updated Mermaid Diagram (IIS Architecture)**

'''mermaid
flowchart TD  
    subgraph "User Interaction & Edge (IIS)"  
        A\["Web Clients or Bots"\] \-- HTTP/S Request \--\> B(IIS Port 80/443);  
        B \-- Handled By \--\> C{ASP.NET Core Middleware App (ANCM)};  
        C \-- Checks \--\> RDB2\[(Redis DB 2 Blocklist)\];  
        C \-- IP Blocked \--\> D\[Return 403\];  
        C \-- UA/Heuristic Blocked \--\> D;  
        C \-- Heuristic Suspicious \--\> F\[Rewrite Path to Tarpit App\];  
        C \-- Passed \--\> G\[Route Request\];  
    end

    subgraph "Backend Services (IIS Applications)"  
        F \--\> H(Tarpit API App \- FastAPI);  
        G \-- Route to /admin \--\> Y(Admin UI App \- Flask);  
        G \-- Route to / \--\> I\[Your Web Application / Other Services\]; %% Route for legitimate traffic

        H \-- Logs Hit \--\> RLOG\["logs/honeypot\_hits.log"\];  
        H \-- Flags IP \--\> RDB1\[(Redis DB 1 Tarpit Flags)\];  
        H \-- Reads/Updates Hop Count \--\> RDB4\[(Redis DB 4 Hop Counts)\];  
        H \-- Updates \--\> MetricsStore\[(Metrics Store)\];  
        H \-- Hop Limit Exceeded \--\> BLOCK\[Add IP to Redis DB 2\];  
        BLOCK \--\> D;  
        H \-- Hop Limit OK, POST Metadata \--\> L(Escalation Engine App \- FastAPI);  
        H \-- Reads Markov Chain \--\> PGDB\[(PostgreSQL Markov DB)\];

        L \-- Uses/Updates \--\> RDB3\[(Redis DB 3 Freq Tracking)\];  
        L \-- Updates \--\> MetricsStore;  
        L \-- If Malicious, POST Webhook \--\> M(AI Service App \- FastAPI);

        M \-- Adds IP \--\> RDB2;  
        M \-- Updates \--\> MetricsStore;  
        M \-- Sends Alerts \--\> P{"Alert Dispatcher"};  
        P \-- Configured Method \--\> Q\[External Systems: Slack, Email, SIEM...\];

        Y \-- Fetches \--\> MetricsEndpoint\["/admin/metrics Endpoint"\];  
        MetricsStore \-- Provides Data \--\> MetricsEndpoint;  
        Y \--\> Z\[Admin Dashboard\];  
    end

    subgraph "Databases & Storage"  
        RDB1; RDB2; RDB3; RDB4; PGDB; MetricsStore;  
        RLOG; U\["./models/\*.joblib"\]; W\["./archives ZIPs"\]; Corpus\["Text Corpus File"\];  
    end

    subgraph "Background & Training Tasks (Windows Task Scheduler / Manual)"  
        RLOG \-- Read By \--\> S(RF Training Script rag/training.py);  
        S \-- Trains \--\> T\[Random Forest Model\];  
        T \-- Saves \--\> U;

        Corpus \-- Read By \--\> MarkovTrain(Markov Training Script rag/train\_markov\_postgres.py);  
        MarkovTrain \-- Populates \--\> PGDB;

        V(Archive Rotator \- Scheduled Task) \-- Manages \--\> W;  
    end

    %% Styling (Optional)  
    classDef iis fill:\#e1f5fe,stroke:\#01579b,stroke-width:2px;  
    classDef csharp fill:\#e8eaf6,stroke:\#303f9f,stroke-width:1px;  
    classDef python fill:\#fff3e0,stroke:\#ef6c00,stroke-width:1px;  
    classDef redis fill:\#ffeb  
'''
