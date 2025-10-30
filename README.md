# Vulnerable Flask SQL Project

This repository now includes automation to set up the [MPC_OWASP_POC](https://github.com/rymarinelli/MPC_OWASP_POC) demonstration application alongside the original vulnerable Flask example.

## MPC_OWASP_POC setup

Run the helper script to clone the upstream project and install its dependencies:

```bash
scripts/setup_mpc_owasp_poc.sh
```

You can optionally pass a target directory name:

```bash
scripts/setup_mpc_owasp_poc.sh demo_app
```

The script attempts to:

1. Clone the upstream repository into the chosen directory.
2. Create a Python virtual environment (defaults to `.venv_mpc`).
3. Install Python dependencies from the cloned project's `requirements.txt`.
4. Install Node dependencies if a `package.json` is present.

If the environment blocks outbound network access, the cloning step will fail. In that case run the script again once network access is available or clone the project manually and re-run the script to handle dependencies.

## Original vulnerable Flask app

The existing `app_vuln.py` file remains unchanged and continues to demonstrate SQL injection vulnerabilities for educational purposes.

Install its dependencies with:

```bash
pip install -r requirements.txt
```

Then run the app with:

```bash
python app_vuln.py
```
