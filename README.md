# SecureVault

A Core Java personal digital security advisor for the CS5304 Java PBL.
The project is developed in small, tested increments. Use fictional account
credentials when demonstrating it.

## Requirements

JDK 21 or newer. No frameworks, database, or external Java libraries.

## Compile and run (PowerShell)

```powershell
New-Item -ItemType Directory -Force out | Out-Null
$sources = (Get-ChildItem src -Recurse -Filter *.java).FullName
javac --release 21 -d out $sources
java -cp out securevault.Main
```

## Run checks

```powershell
$sources = (Get-ChildItem src,tests -Recurse -Filter *.java).FullName
javac --release 21 -d out $sources
java -cp out securevault.TestRunner
```

Read [the project guide](docs/PROJECT_GUIDE.md) for file responsibilities and
Java concepts. Runtime data and compiled files are excluded from Git.
