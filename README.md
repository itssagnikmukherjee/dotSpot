# dotSpot

A powerful web vulnerability scanner built in Python.

## Features

- **SQL Injection (SQLi)** detection with comprehensive payload testing
- **Server-Side Template Injection (SSTI)** scanning
- **Exposed Path Discovery** for sensitive files and directories
- **Cookie Security** analysis
- **HTML Comment** extraction for information leakage
- **JavaScript Analysis** for secrets and sensitive data
- **Base64 Decoding** of embedded data
- **AI-Powered Analysis** via Groq for intelligent scan report summaries

## Installation

```bash
pip install dotspot
```

## Usage

### Scan a target URL

```bash
dotspot scan <target-url>
```

You'll be prompted to choose between vulnerability scanning or flag hunting mode.

### Analyze scan results with AI

```bash
dotspot analyze <scan-report.json>
```

Optionally pass `--api-key YOUR_KEY` or set the `GROQ_API_KEY` environment variable.

### Show help

```bash
dotspot help
```

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `GROQ_API_KEY` | ✅ Yes | — | Your Groq API key for AI-powered analysis |
| `DEFAULT_MODEL` | ❌ No | `llama-3.3-70b-versatile` | Groq model to use |

> **Note:** If `GROQ_API_KEY` is not set, dotSpot will skip the AI Overview phase but all other scans will work normally.

### Setting up your API key

Get a free API key from [console.groq.com](https://console.groq.com/keys), then:

**Linux / macOS:**
```bash
export GROQ_API_KEY=gsk_your_key_here

# Optional: use a different model
export DEFAULT_MODEL=llama-3.1-8b-instant
```

To make it permanent, add the above lines to your `~/.bashrc` or `~/.zshrc`.

**Windows (CMD):**
```cmd
set GROQ_API_KEY=gsk_your_key_here
set DEFAULT_MODEL=llama-3.1-8b-instant
```

**Windows (PowerShell):**
```powershell
$env:GROQ_API_KEY="gsk_your_key_here"
$env:DEFAULT_MODEL="llama-3.1-8b-instant"
```

### Available Models

You can set `DEFAULT_MODEL` to any model supported by Groq. Some popular options:

| Model | Description |
|-------|-------------|
| `llama-3.3-70b-versatile` | Default — best quality |
| `llama-3.1-8b-instant` | Faster, lighter |
| `openai/gpt-oss-120b` | Good balance of speed and quality |

See the full list at [console.groq.com/docs/models](https://console.groq.com/docs/models).

## Requirements

- Python 3.9+

## License

MIT License — see [LICENSE](LICENSE) for details.
