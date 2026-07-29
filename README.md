# Hybrid *pseudo* SIEM & LLM Security Alert Correlation Engine

## Overview

This repository contains the architecture and processing pipeline for an **LLM-Augmented Security Operations Center (SOC) Alerting Engine**. The script/pipeline is designed to ingest, normalize, and correlate dual-layer security log streams—combining traditional Layer 3/4 perimeter firewall logs (such as Cisco ASA Syslog) with modern Layer 7 application, identity, cloud control plane, and satellite infrastructure (Starlink) telemetry.

By leveraging a Large Language Model (LLM) enforcing strict JSON schema constraints, the pipeline identifies complex multi-step attacks, business logic exploits, and semantic threats that standard perimeter firewalls cannot detect on their own.

---

## Primary Objectives

1. **Bridge the Visibility Gap:** Synthesize unstructured network layer logs (`%ASA-X-XXXXXX`) with structured application JSON events (OAuth, gRPC, API gateways, RAG vector pipelines) to detect cross-layer compromises.
2. **Context Window Optimization:** Pre-parse, deduplicate, and normalize high-volume firewall telemetry into OCSF (Open Cybersecurity Schema Framework) standard formats before LLM inference to minimize token overhead and eliminate hallucinations.
3. **Structured Alerting:** Generate standardized, machine-readable JSON security alerts containing threat summaries, granular forensic findings, confidence scores, and automated remediation steps for immediate downstream SOAR/SIEM ingestion.

---

## Supported Threat Categories

The engine evaluates 20+ non-ASA threat vectors across two primary domains, plus specialized satellite/WAN infrastructure alerts:

### 1. Core Security & Behavioral Domain
* **`insider_threat`** — Behavioral Drift & Mass Repository Staging
* **`semantic_exploit`** — Application Logic & Negative Arithmetic Exploits
* **`ai_attack`** — Direct Prompt Injection, System Overrides & Jailbreaks
* **`configuration_drift`** — Kubernetes Manifest Privilege Escalation & Container Root Drift
* **`mfa_fatigue_push`** — MFA Prompt Bombing & Push Notification Exhaustion
* **`mass_assignment_overposting`** — API Schema Over-Posting & Role Injection
* **`low_slow_auth_spray`** — Distributed, Multi-Proxy Identity Credential Spraying
* **`social_engineering_ingress`** — Business Email Compromise (BEC) & Executive Impersonation
* **`business_logic_manipulation`** — Multi-Step Transactional & Currency State Fraud
* **`shadow_ai_dlp`** — Dynamic Source Code Exfiltration to Public AI Services

### 2. Infrastructure, Identity & Network Domain
* **`dns_tunneling_dga`** — Semantic Subdomain Entropy & High-Volume TXT Exfiltration
* **`ad_persistence_forgery`** — Kerberos Golden Ticket Creation & Ticket Lifetime Forgery
* **`api_bola_idor`** — Broken Object Level Authorization & Cross-Tenant Access
* **`cicd_supply_chain`** — Pipeline Contamination & Build-Time Secret Dumping
* **`secrets_leak_detection`** — Hardcoded Cloud Keys in Git Commits & Code Diffs
* **`oauth_app_consent_grant`** — Illicit SaaS Third-Party App Consent & Scope Escalation
* **`session_hijack_fixation`** — Concurrent Geographic Impossible Travel & User-Agent Shifts
* **`ai_key_harvesting`** — Inadvertent API Key & License Exposure in LLM Prompts
* **`graphql_schema_harvesting`** — GraphQL Introspection Probing & Field-Suggestion Leaks
* **`indirect_prompt_injection`** — RAG Vector Database Poisoning & Ingested File Attacks

### 3. Satellite & WAN Perimeter Overlay (Starlink) **IN PROGRESS**
* **`starlink_rf_jamming`** — RF Downlink Noise Spikes & LEO Beam Handoff Failures
* **`starlink_grpc_exploitation`** — Unauthenticated Local gRPC Management API Probing (`192.168.100.1:9201`)
* **`starlink_cgnat_bypassed`** — Anomalous Ground Station POP Shifts & OSPF Latency Anomalies
* **`starlink_shadow_wan`** — Rogue Satellite Egress Bypassing Centralized ASA Perimeter Rules

---

## Data Pipeline Architecture
