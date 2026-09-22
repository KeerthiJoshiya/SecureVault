# SecureVault presentation walkthrough

## Introduce the project

"SecureVault is a Core Java personal digital security advisor. It checks password
habits across a user's online accounts: weak passwords, reuse and predictable
patterns. It calculates a documented score and gives account-specific advice."

## Five-minute demo

Use fictional information throughout. Start `run.cmd`; the Swing window opens.

1. Open the Register tab and create `demo_student` with the fictional login password `DemoLogin!8427`.
2. Log in. Select Security report before adding accounts: the score is N/A.
3. Add these accounts using category 1 (EMAIL), 2 (SOCIAL), and 4 (WORK):

   | Platform | Username | Fictional account password |
   |---|---|---|
   | Mail | learner | Welcome@123 |
   | Social | learner | Welcome@123 |
   | Work | learner | V9!mR2$kL7&zP4@x |

4. Open Security report. Mail and Social are MODERATE, reused and predictable:
   each scores `max(0, 60 - 25 - 20) = 15`. Work scores 100. Overall:
   `round((15 + 15 + 100) / 3) = 43/100`. Two accounts are CRITICAL.
5. Search `mail`; show the matching account without revealing its password.
6. Select Social, choose Update, and change its password to `T6!vN8$bH2&jC5@r`.
   Regenerate the report: Mail scores 40, Social 100, Work 100;
   the overall score becomes 80/100 because reuse was removed for both accounts.
7. Open Recommendations. Show that every account has a separate card and that
   urgent accounts appear first instead of mixing all suggestions together.
8. For the novelty demonstration, set Mail to `FamilyX@2025` and Social to
   `FamilyX@2026`. The report marks both as similar across different platforms,
   subtracts 15 points, and names the related platform without displaying either password.
9. Log out, exit, restart, and log in. Show that updated accounts remain.
10. Demonstrate deletion first with cancellation, then confirmation if desired.

For a lockout demo, log out and submit a wrong password five times. Restarting
does not remove the 60-second lock. Automated checks demonstrate expiry instantly
through a controlled clock instead of waiting during a viva.

## Trace one operation

Add account: `ConsoleUI.add` -> `AccountService.add` -> `Account` validation ->
`FileStore.saveAccounts` -> `VaultEncryption.encrypt` -> encrypted file.
Only after a successful save does the service add the object to its live list.

Report: `ConsoleUI` -> `SecurityAnalysisEngine` -> four `SecurityCheck`
implementations -> `RiskAnalyzer` -> `SecurityAdvisor` -> `SecurityReport` -> UI.

## Questions you should be able to answer

| Question | Simple answer |
|---|---|
| What is a class/object? | Account is the blueprint; my Mail entry is one object created from it. |
| Where is encapsulation? | Account's fields are private, and methods provide controlled access. |
| Why packages? | They group responsibilities and separate UI, data, services, and security. |
| Where is abstraction? | SecurityCheck defines what a check must do without specifying its algorithm. |
| Where is polymorphism? | The engine calls analyze through SecurityCheck references backed by different checker classes. |
| Where is inheritance? | ValidationException extends Exception and inherits Java's exception behavior. |
| Why an enum? | Only allowed category, strength, and risk values can be represented. |
| Why a List? | It holds an ordered collection of accounts or findings. |
| Why a Map? | It associates IDs with results and groups potential duplicate passwords. |
| Why a Set? | It prevents duplicate pattern reasons and detects duplicate persisted IDs. |
| What are generics? | List<Account> means the list contains Account objects, checked by the compiler. |
| Where are streams? | Report counts and account searching use filter/count and lambdas. |
| How are exceptions handled? | Input mistakes, file failures, and cryptographic errors are reported separately. |
| What is finally? | Cleanup that runs even when an exception occurs; we clear temporary password arrays. |
| What is try-with-resources? | Java automatically calls close on the file store and session. |
| Why hashing and encryption? | Login needs verification; saved account passwords must be read again for analysis. |
| What is a salt? | Random data used in derivation so equal passwords do not get equal stored verifiers. |
| Why not a database? | The approved scope uses file I/O; FileStore isolates persistence so it can change later. |
| What makes this different? | It detects exact reuse and related password families across different platforms, then explains the relationship without storing passwords in the finding. |
| Is 100/100 a security guarantee? | No. It means no deductions under the documented educational rules. |

## Suggested order for reading code

1. Main, Account, AccountType, ValidationException.
2. SecurityCheck and its four implementations.
3. AccountAnalysis, RiskAnalyzer, SecurityAdvisor, SecurityReport, engine.
4. User, AuthenticationService, AccountService.
5. PasswordHasher, VaultEncryption, FileStore.
6. SwingUI, AccountDialog, ConsoleUI, and TestRunner.

Run `test.cmd` to demonstrate repeatable verification. Explain a test's expected
behavior rather than claiming passing tests prove software can never fail.
