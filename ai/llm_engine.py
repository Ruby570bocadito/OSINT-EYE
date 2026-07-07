"""OSINT EYE - AI Engine Module (Ollama Local)"""

import json
import subprocess
from typing import Dict, List, Optional


class OllamaEngine:
    """Ollama LLM integration for local AI analysis"""

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url
        self.available = self._check_connection()

    def _check_connection(self) -> bool:
        """Check if Ollama is running"""
        try:
            import requests

            response = requests.get(f"{self.base_url}/api/tags", timeout=5)
            return response.status_code == 200
        except Exception:
            return False

    def _call_ollama(self, prompt: str, system: str = None) -> str:
        """Call Ollama API"""
        try:
            import requests

            payload = {"model": self.model, "prompt": prompt, "stream": False}

            if system:
                payload["system"] = system

            response = requests.post(
                f"{self.base_url}/api/generate", json=payload, timeout=120
            )

            if response.status_code == 200:
                return response.json().get("response", "")
            else:
                return f"Error: {response.status_code}"

        except Exception as e:
            return f"Connection error: {str(e)}"

    def analyze_findings(self, osint_data: Dict) -> str:
        """Analyze OSINT findings with AI"""
        prompt = self._build_analysis_prompt(osint_data)

        system_prompt = """You are a senior penetration tester and red team analyst. 
Analyze the OSINT findings and provide:
1. Most critical attack vectors
2. Recommended priority order for testing
3. Key vulnerabilities to investigate first
Be concise and tactical."""

        return self._call_ollama(prompt, system_prompt)

    def _build_analysis_prompt(self, data: Dict) -> str:
        """Build analysis prompt from OSINT data"""
        prompt = "Analyze these OSINT findings and prioritize attack vectors:\n\n"

        if data.get("subdomains"):
            prompt += f"SUBDOMAINS ({len(data['subdomains'])} found):\n"
            for sub in data["subdomains"][:20]:
                prompt += f"- {sub}\n"
            prompt += "\n"

        if data.get("records"):
            prompt += "DNS RECORDS:\n"
            for rtype, values in data["records"].items():
                if values:
                    prompt += f"- {rtype}: {', '.join(values[:3])}\n"
            prompt += "\n"

        if data.get("services"):
            prompt += "DISCOVERED SERVICES:\n"
            for svc in data["services"][:15]:
                prompt += f"- {svc.get('port')}/{svc.get('protocol')}: {svc.get('service')} {svc.get('version', '')}\n"
            prompt += "\n"

        if data.get("wayback"):
            prompt += (
                f"WAYBACK ({data['wayback'].get('total_snapshots', 0)} snapshots):\n"
            )
            if data["wayback"].get("interesting_urls"):
                for url in data["wayback"]["interesting_urls"][:5]:
                    prompt += f"- [{url['pattern']}] {url['url']}\n"
            prompt += "\n"

        prompt += "What are the most promising attack vectors and where should a red team focus first?"

        return prompt

    def generate_attack_hypothesis(self, target: str, findings: Dict) -> str:
        """Generate attack hypothesis"""
        prompt = f"""For target: {target}

Based on the following reconnaissance data:
{json.dumps(findings, indent=2, default=lambda x: list(x) if isinstance(x, set) else str(x))[:2000]}

Generate a step-by-step attack hypothesis in the style of a real red team engagement.
Include initial access, privilege escalation, and persistence vectors.
Be specific and actionable."""

        system_prompt = """You are a red team operator. Generate realistic attack paths based on 
reconnaissance findings. Be specific about techniques and tools."""

        return self._call_ollama(prompt, system_prompt)

    def suggest_exploits(self, services: List[Dict]) -> str:
        """Suggest potential exploits for discovered services"""
        prompt = "For these services, suggest relevant exploit frameworks and techniques:\n\n"

        for svc in services:
            prompt += f"- {svc.get('service')}:{svc.get('version', 'unknown')} on port {svc.get('port')}\n"

        prompt += (
            "\nProvide specific tool recommendations (Metasploit, ExploitDB, etc.)"
        )

        system_prompt = """You are a penetration testing expert. Recommend specific 
exploitation techniques and available tools for each service."""

        return self._call_ollama(prompt, system_prompt)


class RiskScorer:
    """AI-powered risk scoring"""

    def __init__(self, ollama: OllamaEngine = None):
        self.ollama = ollama or OllamaEngine()

    def calculate_risk_score(self, findings: Dict) -> Dict:
        """Calculate risk score based on findings"""
        score = 0
        factors = []

        if findings.get("subdomains"):
            sub_count = len(findings["subdomains"])
            score += min(sub_count * 2, 20)
            factors.append(f"{sub_count} subdomains discovered")

        if findings.get("services"):
            critical_ports = [21, 22, 23, 25, 445, 3389, 5900, 8080]
            for svc in findings["services"]:
                if svc.get("port") in critical_ports:
                    score += 10
                    factors.append(f"Critical port open: {svc['port']}")

        if findings.get("wayback", {}).get("interesting_urls"):
            score += 15
            factors.append("Interesting Wayback URLs found")

        score = min(score, 100)

        severity = "LOW"
        if score >= 70:
            severity = "CRITICAL"
        elif score >= 50:
            severity = "HIGH"
        elif score >= 30:
            severity = "MEDIUM"

        return {"score": score, "severity": severity, "factors": factors}


class AIEngine:
    """Main AI orchestrator"""

    def __init__(self, model: str = "llama3"):
        self.ollama = OllamaEngine(model=model)
        self.risk_scorer = RiskScorer(self.ollama)

        if not self.ollama.available:
            print("[!] Ollama not available - AI features disabled")
            print("[!] Install Ollama: https://ollama.ai/")

    def analyze(self, findings: Dict) -> Dict:
        """Perform full AI analysis"""
        results = {"ollama_available": self.ollama.available, "risk_score": {}}

        if self.ollama.available:
            results["analysis"] = self.ollama.analyze_findings(findings)
            results["attack_hypothesis"] = self.ollama.generate_attack_hypothesis(
                findings.get("domain", "unknown"), findings
            )
            results["risk_score"] = self.risk_scorer.calculate_risk_score(findings)
        else:
            results["analysis"] = "Ollama not available"
            results["risk_score"] = self.risk_scorer.calculate_risk_score(findings)

        return results

    def generate_redteam_playbook(self, findings: Dict) -> Dict:
        """Act as an AI Agent and generate an execution playbook"""
        if not self.ollama.available:
            return {"playbook": "Ollama not available - Cannot generate Agent Playbook"}

        prompt = f"""Based on the following exact OSINT findings:
{json.dumps(findings, indent=2, default=lambda x: list(x) if isinstance(x, set) else str(x))[:3000]}

Assume the role of the Lead Red Teamer. The user is a junior pentester waiting for your orders.
Give them a tactical, step-by-step Execution Playbook. 
You MUST provide the EXACT terminal commands to run (e.g., nmap, sqlmap, curl, gobuster) against specific IPs, urls, or domains discovered.
Be direct, highly action-oriented, and base all payloads strictly on the technologies/ports found.
"""
        system_prompt = (
            "You are an elite Red Team Lead giving live CLI commands to your operator. "
            "Output a markdown playbook. Prioritize the most critical path to Initial Access. "
            "Always give the exact bash/terminal commands using the real IPs/hostnames from the findings."
        )

        playbook = self.ollama._call_ollama(prompt, system_prompt)
        return {"playbook": playbook}


if __name__ == "__main__":
    print("[*] Testing AI Engine...")

    engine = AIEngine()

    if engine.ollama.available:
        print("[+] Ollama connected!")

        test_data = {
            "domain": "example.com",
            "subdomains": ["www.example.com", "api.example.com", "admin.example.com"],
            "services": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 8.0"},
                {"port": 80, "service": "http", "version": "Apache 2.4"},
            ],
        }

        result = engine.analyze(test_data)
        print(
            f"\n[Risk Score] {result['risk_score']['score']}/100 ({result['risk_score']['severity']})"
        )
    else:
        print("[!] Ollama not running. Start with: ollama serve")
