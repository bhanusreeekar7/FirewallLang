#!/usr/bin/env python3
"""FirewallLang Master Project Orchestrator (v1.0.0 Final).

Launches the complete end-to-end FirewallLang compiler, optimizer, and ML risk evaluation system.
Supports:
  1. Full-Stack Web Mode (FastAPI + Vite React App)
  2. Standalone Terminal CLI Mode (--cli / --demo)
  3. Automated Quality Verification Test Suite (--test)
"""
import os
import sys
import time
import subprocess
import webbrowser
from pathlib import Path

ROOT_DIR = Path(__file__).resolve().parent
BACKEND_DIR = ROOT_DIR / "backend"
FRONTEND_DIR = ROOT_DIR / "frontend"
VENV_PYTHON = BACKEND_DIR / ".venv" / "Scripts" / "python.exe"

# Fallback to system python if venv python does not exist
PYTHON_EXE = str(VENV_PYTHON) if VENV_PYTHON.exists() else sys.executable


def print_banner():
    banner = r"""
========================================================================================
   ____ _                      _ _ _                          
  |  ___(_)_ __ _____      ____ _| | | |    __ _ _ __   __ _   
  | |_  | | '__/ _ \ \ /\ / / _` | | | |   / _` | '_ \ / _` |  
  |  _| | | | |  __/\ V  V / (_| | | | |__| (_| | | | | (_| |  
  |_|   |_|_|  \___| \_/\_/ \__,_|_|_|_____\__,_|_| |_|\__, |  
                                                       |___/   
  Compiler-Based DSL for Firewall Rules with ML-Assisted Misconfiguration Detection
  Status: 100% COMPLETE | Review-3 / Final Stage Production Release
========================================================================================
    """
    print(banner)


def check_and_prepare_ml_model():
    """Ensures dataset is generated and Random Forest model is trained."""
    model_path = BACKEND_DIR / "app" / "analysis" / "models" / "firewall_risk_rf.pkl"
    if not model_path.exists():
        print("[*] Model artifact not found. Generating synthetic dataset and training Random Forest classifier...")
        subprocess.run([PYTHON_EXE, str(BACKEND_DIR / "app" / "analysis" / "generate_dataset.py")], check=True)
        subprocess.run([PYTHON_EXE, str(BACKEND_DIR / "app" / "analysis" / "train_model.py")], check=True)
    else:
        print(f"[OK] Random Forest Model Artifact Verified: {model_path.name}")


def run_tests():
    """Runs full automated unit and integration test suite."""
    print("\n[*] Executing Automated Test Suite across all compiler and ML modules...")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND_DIR)
    res = subprocess.run([PYTHON_EXE, "-m", "pytest", "backend"], cwd=str(ROOT_DIR), env=env)
    return res.returncode == 0


def run_cli_demo():
    """Runs interactive command line compiler demo."""
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND_DIR)
    subprocess.run([PYTHON_EXE, str(ROOT_DIR / "cli.py"), "--demo", "--optimize", "--target", "nftables"], env=env)


def run_fullstack():
    """Launches FastAPI backend server and Vite frontend concurrently."""
    check_and_prepare_ml_model()

    print("\n[*] Starting FirewallLang FastAPI Backend Server (http://127.0.0.1:8000)...")
    env = os.environ.copy()
    env["PYTHONPATH"] = str(BACKEND_DIR)

    backend_proc = subprocess.Popen(
        [PYTHON_EXE, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", "8000"],
        cwd=str(BACKEND_DIR),
        env=env,
    )

    print("[*] Starting FirewallLang React Frontend (http://127.0.0.1:5173)...")
    frontend_proc = subprocess.Popen(
        ["npm", "run", "dev"],
        cwd=str(FRONTEND_DIR),
        shell=True,
    )

    time.sleep(2)
    print("\n" + "=" * 80)
    print("  [SUCCESS] FIREWALLLANG APPLICATION IS RUNNING!")
    print("  - Web Interface: http://127.0.0.1:5173")
    print("  - API Docs:      http://127.0.0.1:8000/docs")
    print("  - Press Ctrl+C in this terminal to gracefully shut down.")
    print("=" * 80 + "\n")

    try:
        webbrowser.open("http://127.0.0.1:5173")
    except Exception:
        pass

    try:
        backend_proc.wait()
        frontend_proc.wait()
    except KeyboardInterrupt:
        print("\n[*] Shutting down FirewallLang servers...")
        backend_proc.terminate()
        frontend_proc.terminate()
        print("[*] Servers stopped.")


def main():
    print_banner()

    if "--test" in sys.argv:
        success = run_tests()
        sys.exit(0 if success else 1)

    if "--cli" in sys.argv:
        check_and_prepare_ml_model()
        run_cli_demo()
        sys.exit(0)

    # Default: launch fullstack application
    run_fullstack()


if __name__ == "__main__":
    main()
