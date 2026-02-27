<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=0,1&height=200&text=Reddit%20Flux&fontSize=50&fontAlignY=35&desc=Deterministic%20Reddit%20CLI%20for%20read%20and%20publish%20workflows&descAlignY=55&fontColor=ffffff" width="100%" />

</div>

<!-- readme-gen:start:badges -->
<p align="center">
  <img alt="Python" src="https://img.shields.io/badge/python-3.10%2B-blue?style=flat-square&logo=python&logoColor=white" />
  <img alt="Version" src="https://img.shields.io/badge/version-0.1.0-7c3aed?style=flat-square" />
  <img alt="Repo" src="https://img.shields.io/badge/repo-reddit--flux-111827?style=flat-square&logo=github" />
</p>

<p align="center">
  <img src="https://skillicons.dev/icons?i=py&theme=dark" alt="Tech Stack" />
</p>
<!-- readme-gen:end:badges -->

> Query Reddit predictably in automation-friendly JSON mode, without OAuth for public reads.
> Switch to OAuth only when you need user actions like posting, messaging, voting, or inbox workflows.

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=0,1&height=1" width="100%" />

## ✨ Highlights

<table>
<tr>
<td width="50%" valign="top">

### 🔓 Public Read Mode
Read subreddits, posts, threads, search, and user history with `REDDIT_PUBLIC_ONLY=1` and no OAuth secrets.

</td>
<td width="50%" valign="top">

### 🔐 OAuth for Write Actions
Post creation, replies, edits, votes, save/unsave, inbox, and direct messages are protected behind user auth.

</td>
</tr>
<tr>
<td width="50%" valign="top">

### 🧭 Deterministic CLI Design
Clear subcommands, explicit flags, and stable structured output for scripting and OpenClaw-style workflows.

</td>
<td width="50%" valign="top">

### 🧾 JSON-first Output
Use `--json` on commands for machine-friendly responses that are easy to pipe, store, and transform.

</td>
</tr>
</table>

## 🚀 Quick Start

```bash
git clone https://github.com/Sheshiyer/reddit-flux.git
cd reddit-flux
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
reddit-cli --help
```

## ⚙️ Authentication Modes

### Public read-only mode (no OAuth)

```bash
export REDDIT_PUBLIC_ONLY=1
export REDDIT_USER_AGENT="mac:reddit-flux:v0.1 (by /u/your_handle)"
```

Works for:
- `subreddit posts|hot|new|top`
- `post thread`
- `search`
- `user profile|comments|posts`

### OAuth mode (required for write + user mailbox actions)

Required:
- `REDDIT_CLIENT_ID`
- `REDDIT_CLIENT_SECRET`
- `REDDIT_USER_AGENT`

For authenticated user actions:
- `REDDIT_REFRESH_TOKEN` *(preferred)*
- or `REDDIT_USERNAME` + `REDDIT_PASSWORD`

Health check:

```bash
reddit-cli auth check --json
```

<img src="https://capsule-render.vercel.app/api?type=rect&color=gradient&customColorList=0,1&height=1" width="100%" />

## 🧩 Command Surface

- `auth check`
- `whoami`
- `subreddit posts|hot|new|top|subscribe|unsubscribe`
- `post thread|create`
- `search`
- `user profile|comments|posts`
- `inbox`, `mentions`, `saved`
- `comment reply|edit`
- `vote`, `save`, `unsave`
- `message send`

## 🗂️ Project Structure

<!-- readme-gen:start:tree -->
```text
📦 reddit-flux
├── 📄 pyproject.toml
├── 📄 README.md
└── 📂 src/
    └── 📂 reddit_cli/
        ├── 📄 __init__.py
        └── 📄 cli.py
```
<!-- readme-gen:end:tree -->

## 📜 License

No license file is currently included. Add a `LICENSE` file before public distribution if you want explicit open-source usage terms.

<!-- readme-gen:start:footer -->
<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=0,1&height=100&section=footer" width="100%" />

Built with ❤️ for deterministic Reddit workflows.

</div>
<!-- readme-gen:end:footer -->
