# RedAmon Wiki

> **Legal Disclaimer**: This tool is intended for **authorized security testing**, **educational purposes**, and **research only**. Never use this system to scan, probe, or attack any system you do not own or have explicit written permission to test. Read the [full disclaimer](../DISCLAIMER.md).

Welcome to the **RedAmon** user guide — a comprehensive, step-by-step reference for getting started with and mastering every feature of the RedAmon AI-powered red team framework.

> **New here?** Start with [Getting Started](1.-Getting-Started) to install and launch RedAmon, then follow the guide sequentially.

---

## Quick Navigation

| # | Page | What You'll Learn |
|---|------|-------------------|
| 1 | [Getting Started](1.-Getting-Started) | Prerequisites, installation, environment setup, first launch |
| 2 | [User Management](2.-User-Management) | Creating users, switching between users, deleting users |
| 3 | [Creating a Project](3.-Creating-a-Project) | Setting up a target, configuring scan modules, the 11-tab project form |
| 4 | [The Graph Dashboard](4.-The-Graph-Dashboard) | Main interface tour — toolbar, 2D/3D graph, data table, node details, bottom bar |
| 5 | [Running Reconnaissance](5.-Running-Reconnaissance) | Starting scans, real-time logs, the 6-phase pipeline, downloading results |
| 6 | [GVM Vulnerability Scanning](6.-GVM-Vulnerability-Scanning) | Network-level scanning with OpenVAS, scan profiles, viewing results |
| 7 | [GitHub Secret Hunting](7.-GitHub-Secret-Hunting) | Creating a GitHub token, configuring and running secret scans |
| 8 | [AI Agent Guide](8.-AI-Agent-Guide) | Chat interface, agent phases, approval workflows, guidance, reports |
| 9 | [Project Settings Reference](9.-Project-Settings-Reference) | Complete reference for all 180+ configurable parameters |
| 10 | [AI Model Providers](10.-AI-Model-Providers) | Setting up OpenAI, Anthropic, Ollama, OpenRouter, AWS Bedrock |
| 11 | [Attack Surface Graph](11.-Attack-Surface-Graph) | Neo4j graph schema — 17 node types, 20+ relationships |
| 12 | [Data Export & Import](12.-Data-Export-and-Import) | Exporting projects, downloading scan data, Excel export |
| 13 | [Troubleshooting](13.-Troubleshooting) | Common issues, container management, GVM feed sync |

---

## What is RedAmon?

RedAmon is an AI-powered agentic red team framework that automates offensive security operations — from reconnaissance to exploitation to post-exploitation — with zero human intervention. Everything runs inside Docker containers: no security tools needed on your host machine.

**Key capabilities:**

- **Automated Reconnaissance** — 6-phase scanning pipeline that maps an entire attack surface
- **AI-Powered Pentesting** — autonomous agent that reasons, selects tools, and executes exploits
- **Network Vulnerability Scanning** — GVM/OpenVAS integration with 170,000+ NVTs
- **GitHub Secret Hunting** — discover leaked credentials and API keys
- **Attack Surface Graph** — Neo4j knowledge graph with 17 node types
- **180+ Project Settings** — fine-grained control over every tool and behavior
- **400+ AI Models** — support for 5 providers including local models via Ollama
