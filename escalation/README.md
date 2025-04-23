# **Escalation Engine Service**

This directory contains the Python code for the Escalation Engine microservice (escalation\_engine.py).

## **Purpose**

The Escalation Engine is a FastAPI application responsible for analyzing metadata associated with suspicious web requests, typically forwarded from the Tarpit API or another detection mechanism.

Its key functions include:

* Receiving request details (IP, User-Agent, headers, path, etc.).  
* Performing real-time frequency analysis using Redis (DB 3).  
* Applying heuristic scoring rules based on request characteristics.  
* Utilizing a pre-trained Machine Learning model (Random Forest) loaded from the models/ directory to predict the likelihood of the request being from a bot.  
* Optionally querying external IP reputation services.  
* Optionally querying external or local classification APIs (e.g., LLMs).  
* Based on a final combined score or classification result, deciding whether the request is malicious.  
* If deemed malicious, forwarding the relevant details via a webhook to the AI Service for blocklisting and alerting.

**Note:** For deployment configuration specific to IIS, refer to the main [IIS Deployment Guide](http://docs.google.com/docs/iis_deployment_guide.md) and the configuration file README located in iis\_configs/escalation\_engine/.