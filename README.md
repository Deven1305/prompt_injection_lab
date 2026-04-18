# Prompt Injection Attack Simulation and Defense
### LLM Security Research Lab — OWASP LLM01:2025

> **Research-level implementation** of prompt injection attacks and multi-layer defenses  
> on LLM-integrated web applications using **Llama 3 (Ollama)** and **Gemini 1.5 Flash**.

---

## What This Project Does

This project demonstrates **Prompt Injection** — the #1 vulnerability in the  
[OWASP Top 10 for LLM Applications (LLM01:2025)](https://genai.owasp.org/llmrisk/llm01-prompt-injection/).

It implements the attack taxonomy from **Liu et al. (2023)** *(arXiv:2306.05499)* and  
defenses informed by **OWASP LLM01** and **Chen et al. (2024)** *(StruQ, arXiv:2402.06363)*.

| Component | Description |
|---|---|
| `vulnerable/app.py` | Flask chatbot with **zero security** — attack surface |
| `hardened/app.py` | Same chatbot with **4-layer defense** |
| `attacker/attack.py` | Automated PoC — 5 payloads × 2 models |
| `report/generate_report.py` | Auto-generates professional PDF report |

---

## Research Contributions

- **Dual-model comparison**: Llama 3 (local) vs Gemini 1.5 Flash (cloud) — quantifies  
  how model safety fine-tuning affects injection success rate
- **5-payload taxonomy** aligned with Liu et al. (2023) HouYi framework categories
- **4-layer defense architecture** validated against all 5 payload categories
- **Automated evidence collection** → structured JSON → professional PDF report

---

## Quick Start

### 1. Clone and install dependencies

```bash
git clone https://github.com/your-username/prompt-injection-lab
cd prompt-injection-lab
pip install -r requirements.txt
```

### 2. Set up environment variables

```bash
cp .env.example .env
# Edit .env — add your Gemini API key
# Get free key: https://aistudio.google.com → Get API Key
```

### 3. Install and start Ollama (Llama 3 — free, local)

```bash
# Linux/Mac
curl -fsSL https://ollama.com/install.sh | sh

# Windows: download installer from https://ollama.com

# Pull Llama 3 model (~4.7 GB)
ollama pull llama3

# If RAM < 8GB, use compressed version (~2.2 GB)
ollama pull llama3:8b-instruct-q4_0

# Start Ollama server (keep this terminal open)
ollama serve
```

### 4. Start both applications (two separate terminals)

```bash
# Terminal 1 — Vulnerable app
python vulnerable/app.py

# Terminal 2 — Hardened app
python hardened/app.py
```

### 5. Run the automated attack

```bash
python attacker/attack.py
```

### 6. Generate PDF report

```bash
python report/generate_report.py
# Output: results/Prompt_Injection_Security_Report.pdf
```

---

## File Structure

```
prompt-injection-lab/
├── vulnerable/
│   └── app.py              # Flask chatbot — NO security controls
├── hardened/
│   └── app.py              # Flask chatbot — 4-layer defense
├── attacker/
│   └── attack.py           # Automated PoC (5 payloads × 2 models × 2 targets)
├── report/
│   └── generate_report.py  # PDF report generator
├── results/
│   ├── results.json        # Auto-generated attack evidence
│   └── Prompt_Injection_Security_Report.pdf
├── screenshots/            # Evidence screenshots
├── .env.example            # Environment variable template
├── requirements.txt
└── README.md
```

---

## Attack Payload Taxonomy (Liu et al. 2023)

| ID | Category | Description |
|---|---|---|
| P1 | Direct Injection | Classic instruction override — "ignore all previous instructions" |
| P2 | Role/Persona Injection | Identity replacement — forces model to adopt unrestricted persona |
| P3 | Social Engineering | Authority-claim attack — exploits RLHF helpfulness bias |
| P4 | Separator Injection | HouYi Separator Component — context partition attack |
| P5 | Indirect/Obfuscated | Task-wrapping — hides injection inside legitimate outer request |

---

## Defense Architecture

```
User Input
    │
    ▼
┌─────────────────────────────┐
│  Layer 1: Keyword Blocklist │  ← catches P1, P2, P3
│  (unicode-normalized regex) │
└──────────────┬──────────────┘
               │ (if passed)
               ▼
┌──────────────────────────────┐
│  Layer 2: Separator Patterns │  ← catches P4 (HouYi-style attacks)
│  (Liu et al. 2023 §4.2)      │
└──────────────┬───────────────┘
               │ (if passed)
               ▼
┌──────────────────────────────┐
│  Layer 3: Structural         │  ← hardens prompt boundary (Chen et al. 2024)
│  Prompt Isolation            │
└──────────────┬───────────────┘
               │
               ▼
           [ LLM Call ]
               │
               ▼
┌──────────────────────────────┐
│  Layer 4: Output Scanning    │  ← catches P5, bypassed attacks
│  (OWASP LLM03)               │
└──────────────┬───────────────┘
               │
               ▼
          Safe Response
```

---

## References

1. Liu, Y. et al. (2023). *Prompt Injection attack against LLM-integrated Applications.* arXiv:2306.05499
2. Greshake, K. et al. (2023). *Not What You've Signed Up For.* arXiv:2302.12173
3. OWASP. (2025). *LLM01:2025 Prompt Injection.* OWASP Top 10 for LLMs
4. Chen, S. et al. (2024). *StruQ: Defending against prompt injection.* arXiv:2402.06363

---

## Disclaimer

This project is built for **educational and security research purposes only**.  
All credentials in the system prompt are **completely fake and simulated**.  
Do not deploy the vulnerable application in any production or public environment.