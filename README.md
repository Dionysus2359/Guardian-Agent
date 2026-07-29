# Guardian Agent

This repository contains the source code for the Guardian Agent project.

## Repository Structure

- `collector/` — Data Ingestion team pulling live RBAC and audit logs.
- `agents/` — LangGraph state machine and core orchestrator.
- `backend/` — FastAPI wrapper and execution controller logic.
- `frontend/` — Streamlit dashboard and approval queue UI.
- `k8s/` — Kubernetes manifests, role definitions, and kind configurations.
- `docs/` — Design Document and architecture diagrams.

## Setup Instructions

1. Clone the repository.
2. Initialize the Python virtual environment.
3. Install dependencies from `requirements.txt` (to be added).
