# langgraph_stage_03.py

from typing import Annotated, Sequence, TypedDict
from langchain_core.messages import BaseMessage, SystemMessage, HumanMessage
from langchain_core.tools import tool
from langgraph.graph.message import add_messages
from langgraph.graph import StateGraph, END
from langgraph.prebuilt import ToolNode
from langchain_ollama import ChatOllama

import subprocess
import requests

# ------------------ AGENT STATE ------------------
class AgentState(TypedDict):
    messages: Annotated[Sequence[BaseMessage], add_messages]

# ------------------ LLM SETUP ------------------
llm = ChatOllama(model="mistral:7b")

# ------------------ TOOL: NMAP SCAN ------------------
@tool
def run_nmap_and_parse(ip_address: str) -> str:
    """
    Scan all TCP ports of the given IP address and return port, service, and version info.
    """
    print(f"Scanning {ip_address} with Nmap...\n")
    try:
        result = subprocess.run(
            ["nmap", "-sCV", "-T4", "-p-", ip_address],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        if result.returncode != 0:
            return f"Nmap scan failed:\n{result.stderr}"
        
        return result.stdout

    except Exception as e:
        return f"Error during Nmap scan: {e}"

# ------------------ TOOL: NVD CVE SEARCH ------------------
@tool
def search_nvd_cves(service: str, version: str, limit: int = 10) -> list:
    """
    Search for CVEs using the official NVD API based on service name and version.
    Returns a list of CVEs with description, score, date, and link.
    """
    api_key = "8cc770c5-150a-42f0-b398-e620022736a2"  # Use your key here
    query = f"{service} {version}"
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": query, "resultsPerPage": limit}

    try:
        response = requests.get(base_url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        cve_items = data.get("vulnerabilities", [])
        cve_list = []

        for item in cve_items:
            cve_id = item["cve"]["id"]
            desc = item["cve"]["descriptions"][0]["value"]
            metrics = item["cve"].get("metrics", {})
            cvss = None

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV30" in metrics:
                cvss = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
            elif "cvssMetricV2" in metrics:
                cvss = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

            published = item["cve"]["published"]
            url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

            cve_list.append({
                "cve": cve_id,
                "description": desc,
                "cvss": cvss,
                "published": published,
                "url": url
            })

        return cve_list

    except Exception as e:
        return [{"error": f"Error fetching CVEs from NVD: {e}"}]

# ------------------ TOOL BINDING ------------------
tools = [
    run_nmap_and_parse,
    search_nvd_cves
]

llm_with_tools = llm.bind_tools(tools)

# ------------------ LLM CALL ------------------
def llm_call(state: AgentState) -> AgentState:
    system_prompt = SystemMessage(
        content=(
            "You are a helpful and intelligent cybersecurity analyst assistant. "
            "You have access to tools for scanning devices (Nmap) and finding known vulnerabilities (NVD CVEs). "
            "Always use tools to gather technical information unless the user question is general knowledge."
        )
    )
    response = llm_with_tools.invoke([system_prompt] + state["messages"])
    return {"messages": [response]}

# ------------------ DECISION HANDLER ------------------
def decision(state: AgentState):
    last_message = state["messages"][-1]
    if not getattr(last_message, "tool_calls", None):
        return "end"
    return "continue"

# ------------------ GRAPH CREATION ------------------
graph = StateGraph(AgentState)
graph.add_node("agent", llm_call)
tool_node = ToolNode(tools=tools)
graph.add_node("tools", tool_node)

graph.set_entry_point("agent")
graph.add_conditional_edges(
    "agent", decision, {"continue": "tools", "end": END}
)
graph.add_edge("tools", "agent")
app = graph.compile()

# ------------------ STREAM PRINTING ------------------
def print_stream(stream):
    for s in stream:
        message = s["messages"][-1]
        if hasattr(message, "pretty_print"):
            message.pretty_print()
        else:
            print(message)

# ------------------ EXAMPLES ------------------
if __name__ == "__main__":
    # Example 1: Full scan and CVE finding
    inputs = {"messages": [HumanMessage(content="Scan 192.168.8.195 and find vulnerabilities for each open port.")]}
    print("---- Cybersecurity Scan ----")
    print_stream(app.stream(inputs, stream_mode="values"))
