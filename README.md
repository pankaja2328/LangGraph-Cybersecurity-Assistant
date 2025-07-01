# 🛡️ LangGraph Cybersecurity Assistant

An AI-powered cybersecurity assistant built using [LangGraph](https://github.com/langchain-ai/langgraph) and [Ollama](https://ollama.com) with integrated tools for **port scanning** using `nmap` and **vulnerability analysis** using the official [NVD CVE API](https://nvd.nist.gov/developers).

---

## 🚀 Features

- 🔍 Full TCP port scan using `nmap -sCV -T4 -p-`
- ⚙️ Extracts open ports, services, and versions
- 🐛 Fetches known vulnerabilities (CVEs) from the NVD
- 🤖 Local AI-powered assistant using `mistral:7b` via Ollama
- 🧠 Tool-aware LangGraph agent that uses tools when needed
- 📈 Optional visual output of the LangGraph state machine

---

## 🧱 Architecture Overview

```mermaid
flowchart TD
    A[User Input] --> B[LangGraph Agent]
    B --> C{Needs Tool?}
    C -- Yes --> D[ToolNode: Nmap or CVE]
    D --> B
    C -- No --> E[LLM Reply]
````

---

## 📁 Project Structure

```
.
├── langgraph_stage_03.py   # Main LangGraph agent
├── requirements.txt        # Python dependencies
├── README.md               # Documentation
└── langgraph.png           # Optional graph visualization output
```

---

## 🛠️ Installation Guide

### ✅ Prerequisites

* Python 3.10+
* Nmap installed (`sudo apt install nmap`)
* Ollama installed and running (`ollama run mistral`)
* Optional: NVD API key for faster/more reliable CVE lookups

---

### 🔧 Step 1: Install System Packages

```bash
sudo apt update
sudo apt install nmap graphviz graphviz-dev
```

---

### 🔧 Step 2: Clone the Repository

```bash
git clone https://github.com/yourusername/langgraph-cyber-assistant.git
cd langgraph-cyber-assistant
```

---

### 🔧 Step 3: Install Python Dependencies

```bash
# Optional: Create a virtual environment
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

> 💡 If `pygraphviz` fails to install, make sure `graphviz-dev` is installed (`sudo apt install graphviz-dev`).

---

### 🔧 Step 4: Start the Ollama Model

```bash
ollama run mistral
```

This loads the `mistral:7b` model locally and keeps it running.

---

### 🔧 Step 5: (Optional) Get NVD API Key

* Visit: [https://nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key)
* Paste your key into the script:

```python
api_key = "your-nvd-key"
```

---

## ▶️ Usage

Run the assistant:

```bash
python langgraph_stage_03.py
```

Example prompt:

```
Scan 192.168.8.195 and find vulnerabilities for each open port.
```

The assistant will:

1. Run an `nmap` scan
2. Parse open ports, services, and versions
3. Search the NVD for related CVEs
4. Display CVE IDs, descriptions, CVSS scores, and links

---

## 💡 Example Output

```
CVE: CVE-2020-0662
Description: RPC Elevation of Privilege Vulnerability
CVSS: 7.8
Published: 2020-02-11
URL: https://nvd.nist.gov/vuln/detail/CVE-2020-0662
```

---

## ⚙️ Future Improvements

* [ ] Auto-extract services from Nmap and run CVE lookups in batch
* [ ] Export scan and CVE results to JSON or HTML reports
* [ ] Add Web UI using FastAPI or Gradio
* [ ] Add support for Nmap XML parsing
* [ ] Support for CVE filtering by severity or date

---

## 📦 `requirements.txt`

```txt
langchain
langgraph
langchain-core
langchain-ollama
requests
pygraphviz
```

---

## 📜 License

MIT License. Free to use, modify, and distribute with credit.

---

## 🙏 Acknowledgements

* [LangGraph](https://github.com/langchain-ai/langgraph)
* [LangChain](https://github.com/langchain-ai/langchain)
* [Ollama](https://ollama.com)
* [NVD CVE API](https://nvd.nist.gov/developers)
* [Nmap](https://nmap.org)

