# Changelog

This toolkit was built in nine commits on 24 September 2026, and the repository
history was then flattened into a single commit so that the published history
starts clean. The entries below are those commits, in the order they were made,
kept because they record why each change exists: what the review found, the two
defects that made a check report success while checking nothing, the login-name
rules, and the rewrite into English.

The short hashes are the original commit ids. They are no longer reachable from
the branch, only by their full SHA.

The creator script was called skapa-konton.ps1 for most of this development and
is named create-accounts.ps1 now, with its result and log files renamed to
match. The entries keep the names of the time.


## feat: initial release of the AD bulk account toolkit

*2026-09-24, commit 89f1d9e*

Two PowerShell scripts for bulk Active Directory account creation from a CSV
export, with a read-only readiness checker that validates the environment, the
directory and the input file before anything is created.

skapa-konton.ps1 fails fast on an unregistered UPN suffix, a missing OU or
group, a password policy that rejects the configured password length, broken
CSV headers and duplicate account names. It records each password before the
group membership step so a group failure never loses a credential, verifies
that every created account is enabled, and reports accounts it could not
activate.

Test-ADBulkReadiness.ps1 performs the same checks without writing anything to
Active Directory or to disk, and exits non-zero when a check fails.

Includes a demo CSV that triggers the duplicate-name, empty-field and
missing-name paths, and a README with the full workflow, parameter reference,
cleanup commands and troubleshooting table.

## fix: harden the password policy checks and stop swallowing lookup failures

*2026-09-24, commit 1a6eac3*

The preflight read MinPasswordLength, ComplexityEnabled and PasswordHistoryCount
straight off the policy object. If a property ever came back empty the numeric
comparison against PasswordLength silently evaluated as true, so the safety
check that exists to prevent disabled accounts would report success without
checking anything. Both scripts now fail loudly when MinPasswordLength is
missing instead of passing quietly.

The same guard was added to the fine-grained policy (PSO) loop, where a missing
MinPasswordLength was being cast to zero, and PSOs whose AppliesTo could not be
read are now reported as a warning rather than being treated as inapplicable.

The per-account verification now falls back to a plain Get-ADUser when the call
with -Properties Enabled,PasswordLastSet fails, and only evaluates
PasswordLastSet when that property actually came back, so a missing property is
no longer reported as a password that was never set.

The verifier counted failures in one lookup loop but swallowed them in the
other. The check for existing names in the target OU now counts its failures
and warns, so an unreachable directory cannot look like a clean result.

Every ActiveDirectory fact these scripts rely on was re-verified against the
official module reference in MicrosoftDocs/windows-powershell-docs.

## docs: restore Swedish diacritics in the quick-start section

*2026-09-24, commit d172acc*

The Swedish section of the guide was written without å, ä and ö, so words like
"båda", "lägg", "rätta" and "är" read as misspelled Swedish. The prose now
uses the correct characters.

The script console output stays ASCII-only Swedish on purpose, and the guide now
says so: it keeps the log and the result file readable regardless of console code
page or file encoding, and only the character replacement in
Convert-TillAnvandarnamn actually needs the real characters. Quoted output in the
guide remains verbatim.

## docs: add Mermaid flowcharts for the operating flow and the script internals

*2026-09-24, commit 5ae05dc*

The README now opens with two diagrams that GitHub renders natively. The first
shows the operator's path: set the parameters, run the verifier, fix anything it
marks FEL, simulate with -WhatIf, review, then run for real and distribute the
passwords.

The second shows what skapa-konton.ps1 does internally: the seven preflight gates
that all run before the first write, the plan build, and the five states an
account can end in. It makes the two design decisions visible - a failure before
the first write leaves nothing behind, and the password reaches the result file
before the group step, so a group failure cannot lose a credential.

## feat: raise the default password length to 16 characters

*2026-09-24, commit f666696*

The generator and the verifier both defaulted to 12. The default is now 16 in
both scripts and in the parameter table, so the generated password satisfies a
longer minimum on first try instead of being rejected by policy and leaving the
account unactivated.

Both scripts still read the real minimum from the domain policy and from any
fine-grained policy that applies to the target group, and both still refuse to
start when PasswordLength is below what the policy demands, so this only moves
the default, not the check.

## feat: short pre-Windows 2000 name and dotted UPN

*2026-09-24, commit 1139c3c*

The pre-Windows 2000 name (sAMAccountName) is now built short: up to three
letters from the first word of Name plus up to three from the first word of Last
Name, so Per Nilsson Andersson gets pernil. That is the field carrying the
20-character compatibility limit, and the short rule keeps it to six characters,
so the limit is now unreachable by construction rather than by truncation.

The User logon name and the mail address take the other half of the rule: every
space-separated part of both columns, transliterated and joined with dots, so the
same person keeps per.nilsson.andersson@domain.se. Neither the UPN nor the mail
address has a documented length limit, so nothing is truncated there.

Collisions become far more likely at six characters, which gives the existing
resolution loop more work: it checks Active Directory and the accounts already
planned in this run, and appends a counter.

The verifier predicts the same two names, prints the first rows as short name
followed by UPN so the operator sees the result before the run, and reports
whether any short name exceeded six characters. The README documents the split,
including how a multi-part name divided between the Name and Last Name columns
changes the short form while leaving the dotted UPN identical.

## feat: detect people who already exist in AD before creating anything

*2026-09-24, commit be99617*

Both scripts now search Active Directory for each planned person before the first
write, matching on the account name (CN), the short login name, the UPN, the mail
address, and the first and last name together. Every hit is reported with the
person's name and the existing account's distinguished name.

Severity decides the outcome. Blocking findings, which stop the creator before
anything is created: an account with the same name already sits in the target OU,
so the new one cannot be created there, or the UPN is already in use, which would
leave two accounts claiming one logon name. Non-blocking findings let the run
continue: the same name exists elsewhere in the directory, the mail address is
already used, the short login name is taken so the row gets a counter suffix, or a
person with the same first and last name exists under a different account name.

-AllowExistingPerson downgrades the blocking findings to warnings for the case
where the records are known to overlap. The login name resolution now also reports
when the base name was already taken in Active Directory, which is the strongest
hint that the person has an account, and the findings are written to the log, to a
new Namnkontroll column in the result file, and by the verifier before the run.

The filter uses the LDAP display names (name, sAMAccountName, userPrincipalName,
mail, givenName, sn), which about_ActiveDirectory_Filter documents as accepted
alongside the PowerShell property names. Empty values are omitted from the filter
so a blank field can never match the whole directory. The search costs one query
per row.

## refactor: rewrite both scripts and the guide in English

*2026-09-24, commit ae600a1*

The creator and the verifier carried Swedish comments, log messages, check labels
and status strings while the repository, the README and the public documentation
are English. Everything a human reads is now English: the comment-based help, all
comments, every console and log message, the check labels (OK, WARN, FAIL), the
finding prefixes (FAIL:, WARN:), the per-account statuses (SIMULATED, CREATED BUT
UNCERTAIN, GROUP FAILURE, NOT ACTIVATED, Password not set), and the result CSV
column headers, now GivenName;Surname;Company;City;UserName;MailAddress;Password;
NameCheck;Status.

Three helpers were renamed with it: Convert-TillAnvandarnamn to Convert-ToSamName,
Get-KortInloggningsnamn to Get-ShortLoginName and Get-PunktNamn to
Get-DottedLoginName, together with the remaining Swedish parameter and local names.

No logic changed, and that is proved rather than asserted: stripping every comment
and the contents of every string literal from the old and the new file, applying
the rename map to the old one, and comparing the remaining code token streams gives
2727 against 2727 tokens for the creator and 2178 against 2178 for the verifier,
with no differences. Both files remain UTF-8 with a BOM and CRLF endings, the
å/ä/ö replacement data is byte-identical, and both still pass the structural check.

The README follows the scripts: the status list, the troubleshooting quotes, the
check labels, the column name, the flowchart labels and the helper reference. The
Swedish quick-start section is removed now that the scripts and the guide are both
English, and the note about ASCII output is now in English.

Anyone parsing the output should note two changes: the log tag FEL became ERROR,
and the result CSV column names changed.

## refactor: rename the scripts and their output files to English names

*2026-09-24, commit dce7467*

The creator was skapa-konton.ps1, which is Swedish, while the verifier, the guide
and the repository are English. It becomes create-accounts.ps1, and the files it
writes become created-accounts.csv and create-accounts.log. The verifier keeps its
name, which is already English.

Every reference follows: both .EXAMPLE lines, the verifier's -MainScriptPath
default, the default -OutputPath and -LogPath, the help text of both scripts, the
README including the flowchart labels, and the gitignore rule that keeps real
result files out of the repository. The working copies of the helper scripts and
the diagram sources were updated as well.

Nothing else inside the scripts changed. The substitution was done at byte level,
so the UTF-8 BOM and the CRLF line endings are preserved by construction, and both
files still pass the structural check with no reference to the old name remaining.

Anyone with a scheduled task, shortcut or report pointing at the old script path,
or at the old log and result file names, needs those updated.
