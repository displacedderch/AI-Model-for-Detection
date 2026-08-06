# Hybrid *pseudo* SIEM & LLM Security Alert Correlation Engine

## Overview

This repository provides the architecture and processing pipeline for an LLM-Augmented Security Operations Center (SOC) Alerting Engine. The script is built to ingest, normalize, and correlate two types of security log streams. It combines traditional Layer 3/4 perimeter firewall logs, like Cisco ASA Syslog, with modern Layer 7 application, identity, cloud control plane, and possibly satellite infrastructure (such as Starlink) telemetry.

The pipeline uses a Large Language Model (LLM) that follows strict JSON Schema rules. This helps it find complex multi-step attacks, business logic exploits, and semantic threats that standard perimeter firewalls might miss.

---

## Primary Objectives

1. **Bridge the Visibility Gap:** Synthesize unstructured network layer logs (`%ASA-X-XXXXXX`) with structured application JSON events (OAuth, gRPC, API gateways, RAG vector pipelines) to detect cross-layer compromises.
2. **Context Window Optimization:** Pre-parse, deduplicate, and normalize high-volume firewall telemetry into OCSF (Open Cybersecurity Schema Framework) standard formats before LLM inference to minimize token overhead and eliminate hallucinations.
3. **Structured Alerting:** Generate standardized, machine-readable JSON security alerts containing threat summaries, granular forensic findings, confidence scores, and automated remediation steps for immediate downstream SOAR/SIEM ingestion.
4. **Pipeline Trust & Chain Integrity Domain:** Ensures zero-trust protection across the entire AI pipeline by verifying Elasticsearch database boundaries, validating cryptographic model weights on GPU hardware, enforcing isolation, and preventing log poisoning or resource exhaustion attacks against the core reasoning engine.
---

## Supported Threat Categories

The engine evaluates 25+ non-ASA threat vectors across two primary domains, plus specialized satellite/WAN infrastructure alerts:

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

### 3. Pipeline Trust-Chain Integrity
* **`log_store_poisoning`** — indirect injection via crafted log entries in the ES store
* **`es_scope_boundary_audit`** — config-state audit of the read-only zero-trust role, not runtime queries
* **`log_time_correlation_integrity`** — cross-WAN-path timestamp skew (Starlink/optical/GSM)
* **`ospf_trust_violation`** — routing-layer trust violations distinct from normal multi-WAN reconvergence
* **`model_integrity_check`** — weight/provenance verification for the GPU4.0-hosted model
* **`gpu_inference_isolation`** — resource isolation if anything else ever shares the GPU
* **`reasoning_layer_exhaustion`** — volume-based DoS against the single reasoning layer
