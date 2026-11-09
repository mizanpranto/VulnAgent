# VulnAgent

### Local LLM-Powered Application Security Code Analyzer

### Note: This project is just started, this is not the final version. You can call this " mini-MVP 😁".

### Read the ai-test-report.pdf, the default report generated via VulnAgent

VulnAgent is an AI-assisted source code security analysis tool powered by **Ollama** and **Qwen3 8B**.

<img width="1512" height="947" alt="Screenshot 2026-11-09 at 11 15 19 PM" src="https://github.com/user-attachments/assets/763f64d8-a4ed-49bb-80e4-eff11c4068bb" />



It analyzes Python and JavaScript/TypeScript codebases to identify potentially exploitable security weaknesses, explain vulnerability scenarios, and recommend remediation.

VulnAgent combines heuristic-based static analysis with local LLM-powered security reasoning to generate structured vulnerability reports without sending source code to an external AI API.

## Architecture

```text
              Source Code
                   |
                   v
             Project Scanner
                   |
                   v
          Heuristic Detection
           (AST + Patterns)
                   |
                   v
             Ollama API
                   |
                   v
              Qwen3 8B
                   |
                   v
          AI Security Analysis
                   |
                   v
          Vulnerability Findings
                   |
                   v
           Report Generation
                /      \
               v        v
           Markdown    JSON
```

## Key Features

- Local LLM-powered source code analysis
- Python AST-based security checks
- Heuristic vulnerability detection
- AI-assisted vulnerability reasoning
- Evidence-based security findings
- Potential attack-path explanations
- Remediation recommendations
- Markdown and JSON report generation
- Configurable LLM model and Ollama host
- Option to run without an LLM

## Technology Stack

- **Language:** Python
- **Local LLM Runtime:** Ollama
- **AI Model:** Qwen3 8B
- **Static Analysis:** Python AST and pattern-based detection
- **API Integration:** Ollama REST API
- **Reporting:** Markdown and JSON

## Supported Languages

- Python (`.py`)
- JavaScript (`.js`)
- JSX (`.jsx`)
- TypeScript (`.ts`)
- TSX (`.tsx`)

## Vulnerability Categories

The analyzer uses heuristic checks and AI-assisted analysis to investigate potential issues such as:

- SQL Injection
- Command Injection
- Cross-Site Scripting (XSS)
- Dynamic Code Execution
- Insecure Deserialization
- Hardcoded Credentials
- Weak Cryptographic Hashing
- TLS Certificate Verification Disabled
- Debug Mode Exposure
- Authentication and Authorization Weaknesses
- Path Traversal
- Server-Side Request Forgery (SSRF)
- Insecure Direct Object References (IDOR)
- Remote Code Execution (RCE)
- Sensitive Information Exposure
- Security Misconfiguration

*Note: Not every category is independently detected by the heuristic scanner. Detection coverage depends on the source code, available evidence, and LLM analysis.*

## Requirements

- Python 3.10 or later
- Ollama
- Qwen3 8B model
- macOS, Linux, or Windows
- Sufficient RAM to run the selected local LLM

## Installation

### 1. Install Ollama

Download Ollama:

https://ollama.com/download

### 2. Download Qwen3 8B

```bash
ollama pull qwen3:8b
```

### 3. Clone the Repository

```bash
git clone https://github.com/YOUR_USERNAME/VulnAgent.git
cd VulnAgent
```

### 4. Create a Python Virtual Environment

macOS / Linux:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Windows:

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### 5. Install Dependencies

```bash
python -m pip install -r requirements.txt
```

## Usage

### Run AI-Powered Analysis

```bash
python -m vulnagent ./target-project
```

### Run Without AI

Run heuristic-based analysis only:

```bash
python -m vulnagent ./target-project --no-llm
```

### Select a Different Ollama Model

```bash
python -m vulnagent ./target-project --model deepseek-r1:14b
```

### Configure the Ollama Host

```bash
python -m vulnagent ./target-project \
  --ollama-host http://127.0.0.1:11434
```

### Configure the Maximum Number of Files

```bash
python -m vulnagent ./target-project --max-files 100
```

### Specify a Report Location

```bash
python -m vulnagent ./target-project \
  --output reports/security-assessment.md
```

The JSON report is generated automatically alongside the Markdown report.

## Reports

VulnAgent generates two report formats:

| Report | Description |
|---|---|
| Markdown | Human-readable security assessment |
| JSON | Structured vulnerability findings for further processing |

Default output:

```text
vulnagent-report.md
vulnagent-report.json
```

Reports include:

- Project information
- Model information
- Executive summary
- AI-generated vulnerability findings
- Severity and confidence
- File and line references
- CWE identifiers, when provided
- Evidence
- Source and vulnerable sink
- Data-flow explanation
- Potential attack paths
- Potential impact
- Recommended remediation
- Safer code examples
- Heuristic scanner findings
- Scanned file list

## Testing

Run the unit tests:

```bash
python -m unittest discover -s tests -v
```

## Project Structure

```text
VulnAgent/
│
├── vulnagent/
│   ├── __init__.py
│   ├── __main__.py
│   ├── scanner.py
│   ├── ollama_client.py
│   └── report.py
│
├── tests/
│   ├── __init__.py
│   └── test_scanner.py
│
├── requirements.txt
├── README.md
└── .gitignore
```

## Security Notice

VulnAgent is designed for authorized defensive source code review and security research.

- AI-generated findings may contain false positives or false negatives.
- Findings must be manually validated before being treated as confirmed vulnerabilities.
- Heuristic detection does not establish exploitability.
- Do not submit source code that you are not authorized to analyze.
- Local LLM processing helps avoid sending source code to an external AI API, but does not guarantee complete privacy or security of the host environment.

VulnAgent is an experimental portfolio project and is not a replacement for professional application security testing or established SAST solutions.

## Author

Developed as an **AI and Application Security Engineering portfolio project**.

**Technologies:** Python | Ollama | Qwen3 8B | Static Analysis | AI-Assisted Security Review
