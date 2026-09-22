# SecureVault

A Core Java personal digital security advisor for the CS5304 Java PBL.
Analyze password strength, reuse, and predictable patterns in a clean Java Swing
desktop interface, then receive an explainable score and recommendations.
Use fictional account credentials when demonstrating this educational project.

## Requirements

JDK 21 or newer. No frameworks, database, or external Java libraries.

## Quick start on Windows

Open a terminal in this repository and run:

```powershell
.\run.cmd
```

Choose **2. Register**, create a login password of at least 12 characters, then
choose **1. Login**. Add fictional accounts and choose **6. Security report**.
The default application opens a desktop window with login, account management,
security report, and recommendation screens.

All successful account changes are saved automatically. Restarting and logging
in restores them. After five failed logins, wait 60 seconds to try again.
There is no forgotten-password recovery in this version.

## Implemented features

- Registration, login, persistent failed-attempt tracking and timed lockout.
- Separate per-user vaults; add, list, edit, delete and search accounts.
- Password strength, exact reuse, similar-password families, and predictable-pattern checks.
- Per-account risk, overall score, statistics, and risk-sorted recommendation cards.
- Salted PBKDF2 login verifiers and AES-GCM encrypted account persistence.
- Invalid-input handling, confirmation before deletion, and safe end-of-input.
- Repeatable tests for analysis, authentication, persistence and failure cases.
- A clean Swing desktop interface with forms, tables, navigation, and dialogs.

## Manual compile and run (PowerShell)

```powershell
New-Item -ItemType Directory -Force out | Out-Null
$sources = (Get-ChildItem src -Recurse -Filter *.java).FullName
javac --release 21 -encoding UTF-8 -d out $sources
java -cp out securevault.Main
```

## Run checks on Windows

```powershell
.\test.cmd
```

The current suite passes **103 checks**, including real console processes,
restart persistence, timed lockout, user isolation, tampered vaults, and failed
saves. Verified on Temurin JDK 25.0.4 while compiling for Java 21 compatibility.
Application sources also pass `javac -Xlint:all` without warnings. An actual
JDK 21 runtime and non-Windows platforms have not been exercised here.

Or compile manually:

```powershell
$sources = (Get-ChildItem src,tests -Recurse -Filter *.java).FullName
javac --release 21 -encoding UTF-8 -d out $sources
java -cp out securevault.TestRunner
```

## Linux/macOS

```sh
mkdir -p out
find src -name '*.java' > out/sources.txt
javac --release 21 -encoding UTF-8 -d out @out/sources.txt
java -cp out securevault.Main
```

For checks, use `find src tests -name '*.java' > out/sources.txt`, recompile,
and run `java -cp out securevault.TestRunner`.

## Learning and presentation

- [Project guide](docs/PROJECT_GUIDE.md): every file, concept, and security boundary.
- [Analysis rules](docs/ANALYSIS_RULES.md): exact formulas and a worked example.
- [Presentation walkthrough](docs/PRESENTATION.md): a short demo and viva answers.

`src/` is application code, `tests/` holds checks, and `docs/` explains the design.
`build.cmd`, `run.cmd`, and `test.cmd` are Windows helper scripts, not Java classes.
They use the PowerShell included with Windows to collect source filenames.
`out/` and `data/` are generated locally and excluded from Git.

Run from the repository root to use its `data/` folder. For a separate demo vault:
`java -cp out securevault.Main "path/to/demo-data"`.

The app supports one process per data folder, up to 1,000 local users and 500
accounts per user. It uses Swing with file persistence rather than JDBC.
It compiles with `--release 21`; no preview features are used.
Swing is now the default interface. The original console interface remains only
for automated testing and can be started with `java -cp out securevault.Main --console`.
