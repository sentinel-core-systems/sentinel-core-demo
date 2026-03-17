# Terms of Use — Sentinel Core

**DataWizual Security Labs**
Last updated: 2026

---

## Definitions

For the purposes of this Agreement, the following terms shall have the meanings set forth below:

- **"Software"** means Sentinel Core, including all embedded components, modules, scripts,
  configuration files, and documentation provided by the Vendor.
- **"Auditor Core"** means the embedded analytical engine included within the Software,
  operating solely as an internal component and not available as a standalone product.
- **"Vendor"** means DataWizual Security Labs, the developer and licensor of the Software.
- **"Customer"** means the organization or individual that installs, deploys, or uses the Software.
- **"License"** means the non-exclusive, non-transferable right to use the Software
  granted under these Terms.
- **"Machine ID"** means the non-reversible cryptographic hardware fingerprint generated
  by the Software for license binding purposes.
- **"AI Advisory"** means threat analysis, verdicts, and remediation suggestions generated
  by third-party AI services integrated with the Software.

---

## 1. Product Description

Sentinel Core is a deterministic security enforcement system designed to detect and block
unsafe code changes, exposed secrets, insecure configurations, and supply chain risks
before they reach production environments.

The Software includes Auditor Core as an embedded analytical engine that performs static
analysis, vulnerability detection, and AI-assisted threat verification. Auditor Core operates
exclusively as an internal component of Sentinel Core. It is not a separate product, is not
available independently, and carries no separate licensing terms.

---

## 2. AI Advisory Disclaimer

The Software optionally integrates with third-party AI services (including Google Gemini)
to provide threat verification and remediation guidance.

**AI analysis is advisory only.** AI-generated verdicts, findings, and recommendations:

- Do not constitute a guarantee of security or absence of vulnerabilities
- May contain errors, omissions, or false classifications
- Must not be used as the sole basis for any security, operational, or business decision
- Are subject to the terms and limitations of the underlying AI provider

**AI Hallucination Notice.** AI systems may generate inaccurate, incomplete, fabricated,
or misleading outputs, commonly referred to as "hallucinations." The Vendor makes no
representation regarding the correctness, completeness, or reliability of any AI-generated
analysis, recommendation, or verdict produced by the Software.

The Vendor bears no liability for consequences arising from reliance on AI-generated output.
All security decisions, overrides, and remediation actions remain the sole responsibility
of the Customer.

---

## 3. Hardware-Bound Licensing

Each License issued under this Agreement is cryptographically bound to a specific machine
hardware identifier (Machine ID). The following conditions apply:

- A License is valid only on the machine for which it was issued
- Transferring, copying, or reusing a License key on a different machine is strictly prohibited
- The Software performs hardware verification at every initialization
- Attempting to circumvent hardware binding constitutes a material breach of this Agreement
  and shall result in immediate License termination without notice or refund

The Vendor reserves the right to revoke and terminate any License found to be used in
violation of these terms, without prior notice and without obligation to issue a refund.

---

## 4. Machine ID and Data Collection

To enable hardware-bound licensing, the Software generates a Machine ID derived from
system identifiers using a one-way cryptographic hash function. This identifier:

- Does not contain personal data within the meaning of applicable data protection law
- Cannot be used to reconstruct underlying hardware details
- Is used solely for license verification purposes
- Is not transmitted to any external server during normal operation
- Is shared with the Vendor only at the explicit request of the Customer's administrator
  during the licensing process

For organizations subject to the General Data Protection Regulation (GDPR) or similar
legislation, the collection of the Machine ID constitutes a contractual necessity for
license issuance and is processed on the legal basis of Article 6(1)(b) of the GDPR.

---

## 5. Permitted Use

The Software is licensed, not sold. The License grants the Customer the non-exclusive,
non-transferable right to install and operate the Software on licensed machines solely
for the purpose of protecting the Customer's internal development and CI/CD workflows.

The following are expressly prohibited without prior written consent from the Vendor:

- Redistribution, resale, or sublicensing of the Software or any License
- Reverse engineering, decompilation, or disassembly of the Software,
  except where such restriction is prohibited by applicable law
- Modification of any enforcement, licensing, or integrity mechanism within the Software
- Use of the Software as part of a commercial service offering to third parties

---

## 6. Professional Use Requirement

The Software is designed exclusively for use by qualified security professionals.
By deploying the Software, the Customer represents and warrants that:

- The Software will be deployed, configured, and operated by personnel with appropriate
  technical expertise in information security and CI/CD systems
- The Customer's security team retains full professional responsibility for all
  configuration decisions, policy settings, enforcement rules, and operational outcomes
- The Vendor supplies a security enforcement tool — equivalent in principle to any
  professional-grade instrument — and assumes no responsibility for outcomes resulting
  from improper deployment, misconfiguration, inadequate expertise, or misuse by
  the Customer's personnel

The Software is intended solely for lawful security enforcement within the Customer's
own development environment. Any use outside this intended purpose is at the Customer's
sole risk and responsibility.

---

## 7. Human Responsibility and Override Policy

The Software may block commits, flag findings, or generate enforcement decisions based
on its configured rules and AI analysis. The Customer acknowledges that:

- Final decisions to override, ignore, or act on findings remain entirely with
  authorized personnel of the Customer
- The Vendor provides analytical visibility and enforcement tooling — not operational control
- Security outcomes, incident response, and remediation are the sole responsibility
  of the Customer

Overrides must be documented with a written justification as required by the Software's
policy configuration. All enforcement events, including overrides, are recorded in an
immutable audit trail within the Customer's administrative repository.

---

## 8. No Warranty

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED,
INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE, UNINTERRUPTED OPERATION, ERROR-FREE PERFORMANCE, OR COMPLETE DETECTION OF
ALL SECURITY VULNERABILITIES.

The Vendor does not warrant that the Software will identify every security issue present
in a codebase, prevent all security incidents, or operate without interruption in all
technical environments. The Software is a risk reduction tool and does not guarantee
the prevention of security vulnerabilities, breaches, or unauthorized access.

---

## 9. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, THE VENDOR SHALL NOT BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, OR PUNITIVE DAMAGES ARISING
FROM THE USE OR INABILITY TO USE THE SOFTWARE, INCLUDING BUT NOT LIMITED TO SECURITY
INCIDENTS, DATA BREACHES, UNAUTHORIZED ACCESS, PRODUCTION FAILURES, DOWNTIME, BUSINESS
INTERRUPTION, DATA LOSS, OR FINANCIAL LOSSES.

**Liability Cap.** In all cases where liability cannot be fully excluded under applicable law,
the Vendor's total aggregate liability to the Customer shall not exceed the total License
fees paid by the Customer to the Vendor during the twelve (12) months immediately preceding
the event giving rise to the claim.

**Carve-Out.** Nothing in this Agreement excludes or limits the Vendor's liability for:

(a) fraud or fraudulent misrepresentation;
(b) willful misconduct;
(c) gross negligence causing death or personal injury;
(d) any liability that cannot be lawfully excluded or limited under applicable law.

---

## 10. Indemnification

The Customer agrees to indemnify, defend, and hold harmless the Vendor and its officers,
employees, and agents from and against any claims, damages, losses, and expenses
(including reasonable legal fees) arising out of or relating to:

- The Customer's use or misuse of the Software
- Violation of any term of this Agreement by the Customer
- Security incidents, breaches, or failures occurring within the Customer's environment
- Any claim by a third party arising from the Customer's deployment or operation
  of the Software

---

## 11. Third-Party Components

The Software integrates third-party open-source tools including, without limitation,
Gitleaks, Bandit, and Semgrep. These components are distributed under their respective
open-source licenses (including MIT, Apache 2.0, and others). The Vendor makes no
representations regarding the availability, security, accuracy, or continued operation
of third-party tools or services.

Third-party AI services (including Google Gemini) are subject to their own terms of service.
The Customer is responsible for ensuring compliance with applicable third-party terms.

---

## 12. Export Control

The Software, including AI integration components, may be subject to export control
and sanctions laws and regulations of the United Kingdom, the United States, the European
Union, and other applicable jurisdictions.

The Customer agrees not to export, re-export, transfer, or make available the Software,
directly or indirectly, to any person, entity, or destination in violation of applicable
export control or sanctions laws. The Customer represents that it is not located in,
under the control of, or a national of any jurisdiction subject to applicable embargo
or sanctions.

---

## 13. Termination

This License is effective until terminated. The Vendor may terminate this License
immediately and without notice if the Customer:

- Violates any material term of this Agreement
- Attempts to circumvent hardware binding or licensing mechanisms
- Uses the Software in a manner that infringes the rights of the Vendor or any third party

Upon termination, the Customer must immediately cease all use of the Software and
destroy all copies in its possession. Termination does not entitle the Customer to any
refund of License fees paid.

The Customer may terminate this License at any time by ceasing use of the Software
and destroying all copies. Termination by the Customer does not entitle it to any refund.

---

## 14. Governing Law and Dispute Resolution

This Agreement shall be governed by and construed in accordance with the laws of
**England and Wales**, without regard to conflict of law principles.

Any dispute, controversy, or claim arising out of or relating to this Agreement,
including its formation, validity, breach, or termination, shall be referred to and
finally resolved by binding arbitration under the Rules of the London Court of
International Arbitration (LCIA). The seat of arbitration shall be London, England.
The language of arbitration shall be English.

Nothing in this clause shall prevent either party from seeking urgent injunctive or
interim relief from a court of competent jurisdiction.

---

## 15. Acceptance

By installing, executing, or deploying the Software — including by running any
provisioning script, installation command, or initialization procedure — the Customer
and its authorized representative confirm that they have read, understood, and
unconditionally accept these Terms of Use in their entirety.

Acceptance is recorded at the time of installation via the interactive confirmation
prompt presented during setup.

---

© 2026 DataWizual Security Labs. All rights reserved.
