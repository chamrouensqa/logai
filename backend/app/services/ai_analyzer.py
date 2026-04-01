import asyncio
import json
from typing import Optional

from app.core.config import settings
from app.services.parsers.base import ParsedLogEntry
from app.services.detectors.base import DetectionResult

SYSTEM_PROMPT = """You are an expert cybersecurity analyst and SOC (Security Operations Center) investigator.
You analyze log data, security alerts, and suspicious activity to provide clear, actionable intelligence.

Your responses should be:
- Professional and concise
- Technically accurate with specific references to log evidence
- Actionable with clear recommended steps
- Structured with clear sections when appropriate

When analyzing logs, focus on:
- Attack patterns and techniques (map to MITRE ATT&CK when relevant)
- Indicators of Compromise (IoCs)
- Risk assessment and business impact
- Concrete remediation steps
- Whether the attack was successful or blocked
"""


class AIAnalyzer:
    """AI-powered security analysis using OpenAI, Anthropic, or local LLM."""

    def __init__(self):
        self.provider = settings.AI_PROVIDER

    async def generate_summary(
        self,
        entries: list[ParsedLogEntry],
        alerts: list[DetectionResult],
        log_type: str = "unknown",
    ) -> dict:
        """Generate a comprehensive AI summary of the log analysis."""
        context = self._build_analysis_context(entries, alerts, log_type)
        prompt = f"""Analyze the following log analysis results and provide a comprehensive security assessment.

{context}

Provide your analysis in the following JSON format:
{{
    "executive_summary": "2-3 sentence overview for management",
    "technical_summary": "Detailed technical analysis of what happened",
    "risk_level": "critical|high|medium|low|info",
    "key_findings": ["finding1", "finding2", ...],
    "attack_narrative": "Step-by-step narrative of what the attacker did (if applicable)",
    "indicators_of_compromise": ["IoC1", "IoC2", ...],
    "recommended_actions": ["action1", "action2", ...],
    "mitre_techniques": ["technique1", "technique2", ...]
}}

Return ONLY valid JSON, no additional text."""

        response = await self._call_ai(prompt)

        try:
            return json.loads(response)
        except json.JSONDecodeError:
            start = response.find("{")
            end = response.rfind("}") + 1
            if start >= 0 and end > start:
                try:
                    return json.loads(response[start:end])
                except json.JSONDecodeError:
                    pass
            return {
                "executive_summary": response[:500],
                "technical_summary": response,
                "risk_level": "medium",
                "key_findings": [],
                "recommended_actions": [],
            }

    async def investigate(
        self,
        question: str,
        entries: list[ParsedLogEntry],
        alerts: list[DetectionResult],
        chat_history: Optional[list[dict]] = None,
    ) -> str:
        """Answer an investigation question about the logs."""
        context = self._build_analysis_context(entries, alerts)

        messages = []
        if chat_history:
            for msg in chat_history[-10:]:
                messages.append({"role": msg["role"], "content": msg["content"]})

        prompt = f"""Based on the following log analysis data, answer the security analyst's question.

{context}

Question: {question}

Provide a clear, specific answer referencing actual evidence from the logs. Include relevant IP addresses, timestamps, usernames, and line numbers when available."""

        return await self._call_ai(prompt, messages)

    def _build_analysis_context(
        self,
        entries: list[ParsedLogEntry],
        alerts: list[DetectionResult],
        log_type: str = "unknown",
    ) -> str:
        parts = [f"Log Type: {log_type}", f"Total Log Entries: {len(entries)}"]

        # Summarize entry types
        event_types = {}
        ips = {}
        users = {}
        for e in entries:
            et = e.event_type or "unknown"
            event_types[et] = event_types.get(et, 0) + 1
            if e.source_ip:
                ips[e.source_ip] = ips.get(e.source_ip, 0) + 1
            if e.username:
                users[e.username] = users.get(e.username, 0) + 1

        parts.append(f"\nEvent Type Distribution:")
        for et, count in sorted(event_types.items(), key=lambda x: x[1], reverse=True)[:15]:
            parts.append(f"  {et}: {count}")

        parts.append(f"\nTop Source IPs:")
        for ip, count in sorted(ips.items(), key=lambda x: x[1], reverse=True)[:10]:
            parts.append(f"  {ip}: {count} events")

        if users:
            parts.append(f"\nTop Usernames:")
            for user, count in sorted(users.items(), key=lambda x: x[1], reverse=True)[:10]:
                parts.append(f"  {user}: {count} events")

        if alerts:
            parts.append(f"\n--- SECURITY ALERTS ({len(alerts)}) ---")
            for i, alert in enumerate(alerts, 1):
                sev = alert.severity.value if hasattr(alert.severity, "value") else alert.severity
                parts.append(f"\nAlert #{i}: [{sev.upper()}] {alert.title}")
                parts.append(f"  Type: {alert.alert_type}")
                parts.append(f"  Description: {alert.description}")
                if alert.source_ip:
                    parts.append(f"  Source IP: {alert.source_ip}")
                if alert.target_account:
                    parts.append(f"  Target Account: {alert.target_account}")
                if alert.evidence:
                    parts.append(f"  Evidence: {json.dumps(alert.evidence, default=str)[:500]}")

        # Include a sample of interesting log entries
        interesting = [e for e in entries if e.event_type in (
            "login_failed", "login_success", "unauthorized", "forbidden",
            "server_error", "sudo_command", "firewall_block",
        )][:30]

        if interesting:
            parts.append(f"\n--- SAMPLE NOTABLE ENTRIES ({len(interesting)}) ---")
            for e in interesting:
                ts = str(e.timestamp) if e.timestamp else "N/A"
                parts.append(
                    f"  Line {e.line_number}: [{ts}] {e.event_type} | "
                    f"IP: {e.source_ip or 'N/A'} | User: {e.username or 'N/A'} | "
                    f"{(e.message or '')[:150]}"
                )

        return "\n".join(parts)

    async def _call_ai(self, prompt: str, messages: Optional[list[dict]] = None) -> str:
        if self.provider == "openai":
            return await self._call_openai(prompt, messages)
        elif self.provider == "anthropic":
            return await self._call_anthropic(prompt, messages)
        elif self.provider == "local":
            return await self._call_local(prompt, messages)
        else:
            return self._fallback_analysis(prompt)

    async def _call_openai(self, prompt: str, messages: Optional[list[dict]] = None) -> str:
        import httpx
        from openai import (
            APIConnectionError,
            APITimeoutError,
            AsyncOpenAI,
            BadRequestError,
            NotFoundError,
            RateLimitError,
        )

        # Bypass system proxy variables that can break outbound AI requests
        # in local/dev environments.
        http_client = httpx.AsyncClient(trust_env=False, timeout=120.0)
        client = AsyncOpenAI(api_key=settings.OPENAI_API_KEY, http_client=http_client)
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}]
        if messages:
            msgs.extend(messages)
        msgs.append({"role": "user", "content": prompt})

        try:
            # Retry transient network/rate-limit errors to reduce
            # intermittent "AI unavailable" fallbacks.
            delays = [0.0, 1.0, 2.5]
            models = [settings.OPENAI_MODEL]
            if settings.OPENAI_FALLBACK_MODEL and settings.OPENAI_FALLBACK_MODEL not in models:
                models.append(settings.OPENAI_FALLBACK_MODEL)

            last_err = None
            for model in models:
                for delay in delays:
                    if delay:
                        await asyncio.sleep(delay)
                    try:
                        response = await client.chat.completions.create(
                            model=model,
                            messages=msgs,
                            temperature=0.3,
                            max_tokens=4096,
                        )
                        return response.choices[0].message.content
                    except (APIConnectionError, APITimeoutError, RateLimitError) as e:
                        last_err = e
                        continue
                    except (BadRequestError, NotFoundError) as e:
                        # Model may be unavailable to this key/account; try fallback model.
                        last_err = e
                        break
            if last_err:
                raise last_err
            raise RuntimeError("OpenAI call failed without an explicit error")
        finally:
            await http_client.aclose()

    async def _call_anthropic(self, prompt: str, messages: Optional[list[dict]] = None) -> str:
        from anthropic import AsyncAnthropic

        client = AsyncAnthropic(api_key=settings.ANTHROPIC_API_KEY)
        msgs = []
        if messages:
            msgs.extend(messages)
        msgs.append({"role": "user", "content": prompt})

        response = await client.messages.create(
            model=settings.ANTHROPIC_MODEL,
            system=SYSTEM_PROMPT,
            messages=msgs,
            max_tokens=4096,
            temperature=0.3,
        )
        return response.content[0].text

    async def _call_local(self, prompt: str, messages: Optional[list[dict]] = None) -> str:
        import httpx

        url = settings.LOCAL_LLM_URL or "http://localhost:11434/api/chat"
        msgs = [{"role": "system", "content": SYSTEM_PROMPT}]
        if messages:
            msgs.extend(messages)
        msgs.append({"role": "user", "content": prompt})

        async with httpx.AsyncClient(timeout=120.0) as client:
            response = await client.post(url, json={
                "model": "llama3.1",
                "messages": msgs,
                "stream": False,
            })
            data = response.json()
            return data.get("message", {}).get("content", str(data))

    def _fallback_analysis(self, prompt: str) -> str:
        return json.dumps({
            "executive_summary": "AI analysis unavailable. Please configure an AI provider (OPENAI_API_KEY, ANTHROPIC_API_KEY, or LOCAL_LLM_URL).",
            "technical_summary": "No AI provider configured. Detection engine results are available above.",
            "risk_level": "unknown",
            "key_findings": ["AI provider not configured"],
            "recommended_actions": ["Configure an AI provider in .env file"],
        })
