# DevOps Repository Auditing Agent

Autonomous agent that inspects GitHub repositories for DevOps violations and generates an evidence-based JSON report.

## Architecture

The agent follows an explicit loop without frameworks like LangChain or LangGraph:
`Observe -> Reason -> Select Tool -> Execute Tool -> Interpret Results -> Report`

- `agent.py`: CLI entry point and repo sandbox manager
- `tools.py`: Safe inspection tools (`list_files`, `read_file`, `search_code`, `git_log`, CI and dependency checks)
- `agent_modules/agent_loop.py`: Python tool execution loop and fallback heuristic engine
- `agent_modules/llm.py`: Provider client and function calling definitions
- `agent_modules/schema.py`: Pydantic output models and secret sanitization
- `agent_modules/rules.py`: DevOps rule specifications and categories

## Requirements

- Python 3.9+
- Git installed on host
- OpenAI API key (or OpenAI-compatible endpoint)

## Installation

```bash
git clone https://github.com/rehan-akram723/assignment2.git
cd assignment2
pip install -r requirements.txt
```

## Setup

Copy the environment template and set your API key:

```bash
cp .env.example .env
```

Edit `.env`:
```ini
OPENAI_API_KEY=your_key_here
OPENAI_MODEL=gpt-4o-mini
```

## Usage

Run unattended repository inspection:

```bash
python agent.py --repo https://github.com/example/demo-project --output report.json
```

Options:
- `--repo`: Target GitHub URL or local repository path
- `--output`: File path to save output JSON report
- `--model`: LLM model name (default: `gpt-4o-mini`)
- `--max-steps`: Maximum inspection iterations (default: 15)
- `--offline`: Run heuristic inspection without making LLM API calls

## Testing

Run the automated test suite:

```bash
pytest -v
```
