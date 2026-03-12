# Contributing to Enkrypt AI MCP Server

Thank you for your interest in contributing! We welcome contributions of all kinds — bug fixes, new features, documentation improvements, and more.

---

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [How to Contribute](#how-to-contribute)
- [Development Setup](#development-setup)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Issues](#reporting-issues)

---

## Code of Conduct

Please be respectful and constructive in all interactions. We are committed to making this project a welcoming environment for everyone.

---

## Getting Started

1. **Fork** the repository on GitHub.
2. **Clone** your fork locally:

```bash
git clone https://github.com/enkryptai/enkryptai-mcp-server.git
cd enkryptai-mcp-server
```

3. **Add the upstream remote** to keep your fork in sync:

```bash
git remote add upstream https://github.com/enkryptai/enkryptai-mcp-server.git
```

---

## How to Contribute

- **Bug fixes** — Open an issue first to discuss the bug, then submit a PR with a fix.
- **New features** — Open an issue to propose the feature before starting work, so we can align on direction.
- **Documentation** — Improvements to the README, inline comments, or new docs are always welcome.
- **Tests** — Additional test coverage is greatly appreciated.

---

## Development Setup

Ensure you have [`uv`](https://docs.astral.sh/uv/getting-started/installation/) installed, then:

```bash
uv pip install -e .
```

Set your API key in a `.env` file or as an environment variable:

```bash
export ENKRYPTAI_API_KEY=your_api_key_here
```

---

## Submitting a Pull Request

1. Create a new branch from `main`:

```bash
git checkout -b feat/your-feature-name
```

2. Make your changes, keeping commits focused and descriptive.

3. Ensure your changes don't break existing functionality by running any available tests.

4. Push your branch and open a Pull Request against `main`:

```bash
git push origin feat/your-feature-name
```

5. In your PR description, explain:
   - What problem it solves or what feature it adds
   - Any relevant context or trade-offs
   - How to test the changes

We'll review your PR as soon as possible and provide feedback.

---

## Reporting Issues

If you find a bug or have a feature request, please [open an issue](https://github.com/enkryptai/enkryptai-mcp-server/issues) and include:

- A clear description of the problem or request
- Steps to reproduce (for bugs)
- Your environment (OS, Python version, etc.)
- Any relevant logs or error messages

---

## License

By contributing, you agree that your contributions will be licensed under the [Apache 2.0 License](LICENSE).
