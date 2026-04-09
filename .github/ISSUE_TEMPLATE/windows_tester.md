---
name: Windows tester report
about: I tried whySlowLaptop on Windows — here's what worked / broke
title: '[WINDOWS] '
labels: windows, help wanted
---

The Windows version (`win_optimizer.py`) is currently v0.5 — it has the
basic features but lacks the v1.0 additions (File Organizer, Duplicates,
Story Mode, Slowness Diagnosis). I don't own a Windows machine, so reports
from real Windows users are the single most useful contribution right now.

**Your system**
- Windows version: (Windows 10 / Windows 11, 22H2, etc.)
- Python version: run `python --version` in Command Prompt
- Hardware: (laptop model, RAM, SSD vs HDD)

**What I tried**
- Did `python win_optimizer.py` start the dashboard at all? Y / N
- Did the browser auto-open to localhost:8765? Y / N
- Which cards loaded data? Which crashed or stayed empty?

**What broke**
Paste any errors from the Command Prompt window, or describe what looked
wrong on the dashboard.

**What worked**
Tell me what was useful even on the v0.5 build — I want to know what NOT
to break when I port the v1.0 features.

**Are you willing to keep testing?**
Y / N — let me know if I can ping you on subsequent test builds.
