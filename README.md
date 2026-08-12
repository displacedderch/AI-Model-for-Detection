# Hybrid SIEM & LLM Security Alert Correlation Engine via an LLM

## Overview

The repository contains the architecture and processing pipeline for an alerting engine that is augmented with the use of large language models. The script is designed to ingest, normalise, and correlate two kinds of security log streams; it combines traditional Layer 3/4 perimeter firewall logs, for example those from Cisco ASA Syslog, with modern Layer 7 application, identity, cloud control plane, and possibly also telemetry from satellite infrastructure such as Starlink.

The pipeline is based on a Large Language Model (LLM) which adheres to strict JSON Schema rules, enabling it to identify complex multi-step attacks, business-logic exploits, and semantic threats that ordinary perimeter firewalls would probably fail to detect.

---

## Primary Objectives

1. **Bridge the Visibility Gap:** Synthesize unstructured network layer logs (`%ASA-X-XXXXXX`) with structured application JSON events (OAuth, gRPC, API gateways, RAG vector pipelines) to detect cross-layer compromises.
2. **Context Window Optimization:** Pre-parse, deduplicate, and normalize high-volume firewall telemetry into OCSF (Open Cybersecurity Schema Framework) standard formats before LLM inference to minimize token overhead and eliminate hallucinations.
3. **Structured Alerting:** Generate standardized, machine-readable JSON security alerts containing threat summaries, granular forensic findings, confidence scores, and automated remediation steps for immediate downstream SOAR/SIEM ingestion.
4. **Pipeline Trust & Chain Integrity Domain:** Ensures zero-trust protection across the entire AI pipeline by verifying Elasticsearch database boundaries, validating cryptographic model weights on GPU hardware, enforcing isolation, and preventing log poisoning or resource exhaustion attacks against the core reasoning engine.
---

## Supported Threat Categories

The engine evaluates 27+ non-ASA threat vectors across two primary domains, plus specialized satellite/WAN infrastructure alerts:

### Behavioral & Identity Threats
* **`insider_theat`** — Behavioral Drift & Mass Repository Stagin
* **`mfa_fatigue_push`** — MFA Prompt Bombing & Push Notification Exhaustion
* **`low_slow_auth_spray`** — Distributed, Multi-Proxy Identity Credential Spraying
* **`social_engineering_ingress`** — BEC & Executive Impersonation
* **`session_hijack_fixation`** — Impossible Travel & User-Agent Shifts

### Application & API Exploits
* **`semantic_exploit`** — Application Logic & Negative Arithmetic Exploits
* **`mass_assignment_overposting`** — API Schema Over-Posting & Role Injection
* **`api_bola_idor`** — Broken Object Level Authorization & Cross-Tenant Access
* **`business_logic_manipulation`** — Multi-Step Transactional & Currency State Fraud
* **`graphql_schema_harvesting`** — GraphQL Introspection Probing & Field-Suggestion Leaks

### Infrastructure & Configuration Drift
* **`configuration_drift`** — Kubernetes Manifest Privilege Escalation & Container Root Drift
* **`cicd_supply_chain`** — Pipeline Contamination & Build-Time Secret Dumping
* **`secrets_leak_detection`** — Hardcoded Cloud Keys in Git Commits & Code Diffs
* **`dns_tunneling_dga`** — Semantic Subdomain Entropy & High-Volume TXT Exfiltration
* **`ospf_trust_violation`** — Routing-layer trust violations

### Authentication, Authorization & Persistence
* **`ad_persistence_forgery`** — Kerberos Golden Ticket Creation & Ticket Lifetime Forgery
* **`oauth_app_consent_grant`** — Illicit SaaS App Consent & Scope Escalation

### AI-Specific Security Threats
* **`ai_attack`** — Prompt Injection, System Overrides & Jailbreaks
* **`shadow_ai_dlp`** — Source Code Exfiltration to Public AI Services
* **`ai_key_harvesting`** — API Key & License Exposure in LLM Prompts
* **`indirect_prompt_injection`** — RAG Vector DB Poisoning & Ingested File Attacks
* **`model_integrity_check`** — Weight/Provenance Verification for GPU-hosted Model
* **`gpu_inference_isolation`** — Resource Isolation if Sharing GPU
* **`reasoning_layer_exhaustion`** — Volume-based DoS Against Single Reasoning Layer

### Observability, Logging & State Integrity
* **`log_store_poisoning`** — Crafted log-entry injection into ES store
* **`es_scope_boundary_audit`** — Config-state audit of read-only zero‑trust role
* **`log_time_correlation_integrity`** — WAN-path timestamp skew (Starlink/optical/GSM)
