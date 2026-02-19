<img width="1067" height="423" alt="image" src="https://github.com/user-attachments/assets/15248259-5121-4171-817c-76bc8105037e" /> 

# 🧠 What ?
**Pinpoint vulnerabilities with AI-enhanced precision.**
>isn't just another web scanner—it's your intelligent security wingman, combining rigorous traditional scanning logic with the cognitive speed of AI, doesn't just find vulnerabilities; it helps you understand them :)

# ❓ Why ?
not to scan, **to Hunt**
## 1. **SQL Injection (SQLi)**
| Detection |
|-----------|
| <img width="100%" alt="Detection" src="https://github.com/user-attachments/assets/091e37cf-e342-4f35-99b6-bfab6acddee1" /> |

| Prevention |
|------------|
| <img width="100%" alt="Prevention" src="https://github.com/user-attachments/assets/fa39b6a4-acd7-4695-9240-41be799daac6" /> |

## 2. **Server-Side Template Injection (SSTI)**
| Detection |
|-----------|
| <img width="100%" alt="Detection" src="https://github.com/user-attachments/assets/9d440967-9ed0-4731-a3f3-797e403596ce" /> |

| Prevention |
|------------|
| <img width="100%" alt="Prevention" src="https://github.com/user-attachments/assets/a7225fe3-97c2-4f08-969b-724ec0bf1d7c" /> |

## 3. **Exposed Path Discovery**
| Detection |
|-----------|
| <img width="100%" alt="Detection" src="https://github.com/user-attachments/assets/1bce4338-0c75-4c1b-9253-659f0bf9c823" /> |

| Prevention |
|------------|
| <img width="100%" alt="Prevention" src="https://github.com/user-attachments/assets/6adac9aa-9bc0-4086-aaef-5c1d9d0e89b2" /> |

## 4. **Cookie Security Analysis**
| Detection |
|-----------|
| <img width="100%" alt="Detection" src="https://github.com/user-attachments/assets/4368d31f-9405-468b-9229-d28a18558e83" /> |

| Prevention |
|------------|
| <img width="100%" alt="Prevention" src="https://github.com/user-attachments/assets/61b39ba3-7fca-46f0-b996-fd5845593027" /> |
| <img width="999" height="56" alt="image" src="https://github.com/user-attachments/assets/c62f4fb5-f537-4655-9d2f-7522ee6124d6" /> |

## 5. **Comment Leakage**
| Exposed Comments |
|------------------|
| <img width="1009" height="883" alt="image" src="https://github.com/user-attachments/assets/4edca9a5-966e-475e-a4cb-f5263e9768dd" /> |

## 6. **Surface Script Analysis**
| Detection |
|-----------|
| <img width="100%" alt="Detection" src="https://github.com/user-attachments/assets/733019ef-9592-4457-83ab-44b9100abedc" /> |

| Prevention |
|------------|
| <img width="100%" alt="Prevention" src="https://github.com/user-attachments/assets/07646ab0-f90d-498f-87ea-5d8b2f8671ea" /> |

## 7. **Pattern Decoding**
| Detection |
|-----------|
| <img width="100%" alt="Detection" src="https://github.com/user-attachments/assets/df515a02-1adc-4a82-88fc-2b5a300a44a6" /> |

| Prevention |
|------------|
| <img width="100%" alt="Prevention" src="https://github.com/user-attachments/assets/2e924d4b-6479-462e-b7a0-5e3493745c0f" /> |

## 8. **AI-Powered Analysis**
| Fix Suggestions |
|------------------|
| <img width="1020" height="567" alt="image" src="https://github.com/user-attachments/assets/ca38ae9f-69fe-43d6-babd-b54b2a38830d" /> |

## 9. **Generate Report**
| JSON & HTML Report |
|--------------------|
|<img width="1154" height="579" alt="image" src="https://github.com/user-attachments/assets/2ca2a213-dfb3-4220-8fab-6adc93511add" />|

# ⚙️ How ? (Installation)

```bash
pip install dotspot
```

## To run

### 🔍 Scan a target URL

```bash
dotspot scan <target-url>
```
### 👀 To run locally
```bash
git clone https://github.com/itssagnikmukherjee/dotSpot.git
cd dotSpot
./run.sh scan <target-url>
```

### 🤝 Show help

```bash
dotspot help
```

## 🤖 AI Configuration

### 🧩 Environment Variables

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

## 🕵️‍♂️ Requirements 

- Python 3.9+

## 📜 License

MIT License — see [LICENSE](LICENSE) for details.
