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
