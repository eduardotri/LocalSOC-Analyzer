# LocalSOC Analyzer

Local AI-powered SOC investigation and forensic log analysis platform.

## Overview

LocalSOC Analyzer is a local-first security investigation platform designed to support SOC, CSIRT, AppSec and threat hunting activities.

## Main capabilities

- WAF and application log ingestion
- SQLite-based analytical engine
- Forensic evidence preservation
- SHA-256 file integrity verification
- HTTP status analysis
- IP and identity correlation
- IDOR/BOLA investigation indicators
- Object enumeration detection
- MITRE ATT&CK integration
- Local LLM integration through Ollama
- Investigation reports

## Architecture

- Python
- FastAPI
- SQLite
- Ollama
- Local language models

## Requirements

- Windows 10/11
- Python 3.11 or compatible project version
- Ollama
- Sufficient disk space for investigation data

## Security

Do not commit:

- Production logs
- Forensic evidence
- SQLite databases
- Authentication tokens
- API keys
- Passwords
- Environment files
- Local AI models

## Installation

Installation instructions will be documented according to the supported release.

## Project status

Development project.

## Disclaimer

This project is intended for authorized defensive security investigations.
