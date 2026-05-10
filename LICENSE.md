# Mythodikal Anti-Virus — Proprietary Source-Visible License

**Copyright © 2026 Mike Weaver (mythodikalone@gmail.com). All Rights Reserved.**

SPDX-License-Identifier: LicenseRef-MythodikalARR-1.0

This is a **proprietary, source-visible** license. The source code of Mythodikal Anti-Virus (the "Software") is published in the public Git repository so that users, security researchers, and the broader community may **inspect** the code that runs with high privilege on their machines.

Publishing the source does NOT grant any rights to use, copy, modify, distribute, or otherwise exploit the Software. All rights are reserved by the Licensor (Mike Weaver). This license is not OSI-approved "Open Source" and not FSF-approved "Free Software."

If you are looking for a permissive license, this is not it. If you want to use any part of this Software in your own work, you must obtain a separate written license from the Licensor.

---

## 1. Definitions

1.1 **"Software"** means the entire contents of this Git repository, including but not limited to: source code in any language; build scripts; configuration; documentation; design tokens; brand assets; database schemas; YARA rules authored by the Licensor; tests; and any other files committed to the repository, whether on the default branch, any other branch, any tag, or any release artifact.

1.2 **"Compiled Binary"** means any executable, library, installer, or other binary artifact derived from the Software. Compiled Binaries distributed by the Licensor are governed by the End-User License Agreement that accompanies them, not this license.

1.3 **"You"** (or "Your") means the natural person or legal entity exercising permissions granted by, or attempting to exercise permissions over, the Software.

1.4 **"Licensor"** means Mike Weaver (`mythodikalone@gmail.com`), or any successor designated in writing.

1.5 **"Permitted Inspection Use"** means the activities described in Section 2 of this license.

---

## 2. Limited Grant — Permitted Inspection Use

The Licensor grants You a non-exclusive, non-transferable, non-sublicensable, **revocable** permission, free of charge, to do the following with the Software:

2.1 **Read** the source code of the Software for personal, non-commercial purposes such as security research, education, and curiosity.

2.2 **Compile and run** the Software locally on Your own computer for the sole purpose of evaluating its behavior, validating Permitted Inspection Use claims (e.g., "telemetry is off by default"), and security review. Local execution under this clause must NOT be used as a substitute for purchasing or installing officially distributed Compiled Binaries; nothing produced under this clause may be used in any production or operational capacity beyond the personal evaluation use described.

2.3 **Quote, screenshot, or excerpt** small portions of the source code (no more than 50 lines per excerpt; no more than 250 lines cumulative across all uses) for the purposes of: writing a security advisory; writing a technical blog post or article; teaching; academic research; or filing a bug report or vulnerability disclosure with the Licensor. Attribution to "Mythodikal Anti-Virus, © Mike Weaver, All Rights Reserved" must accompany any such excerpt.

2.4 **Submit** bug reports, feature requests, and security disclosures to the Licensor through the channels specified in `SECURITY.md` and the project issue tracker. Section 6 governs the rights in Your submissions.

That is the entirety of the grant. **No other rights are granted, expressly or by implication.**

---

## 3. Prohibited Activities

Without a separate written license from the Licensor, You shall NOT:

3.1 **Copy** the Software, in whole or in part, to any storage location other than: (a) Your own computer's local working copy obtained via `git clone` from the official repository or its official mirrors; (b) Your own backups of that working copy.

3.2 **Distribute, publish, or share** the Software, in whole or in part, including Compiled Binaries derived from the Software, to any third party. This includes (without limitation): forks on public Git hosting; package registries; mirror sites; torrent trackers; cloud storage with public read access; email attachments; physical media; or any other transmission medium.

3.3 **Modify, adapt, translate, or create derivative works** based on the Software, except to the extent required for Permitted Inspection Use under Section 2.2 (local evaluation), and even then, the modified copy must remain on Your local machine and must be deleted no later than thirty (30) days after the evaluation purpose has been satisfied.

3.4 **Sublicense, rent, lease, lend, or sell** the Software or any rights therein.

3.5 **Reverse engineer**, decompile, or disassemble any Compiled Binary distributed by the Licensor, except where such activity is expressly permitted by applicable law notwithstanding this restriction.

3.6 **Remove, alter, or obscure** any copyright, trademark, license, attribution, or other proprietary notice in or on the Software.

3.7 **Use the Software, in whole or in part, to train any machine-learning model, large language model, code-suggestion model, or any other artificial-intelligence system**, including but not limited to indexing the Software in any AI training corpus, retrieval-augmented-generation index, or model fine-tuning dataset, regardless of whether the resulting model is open or closed.

3.8 **Use the Software, in whole or in part, to create, develop, market, or operate any product or service that competes with Mythodikal Anti-Virus**. This includes (without limitation) any anti-virus, anti-malware, endpoint detection and response (EDR), file scanning, threat intelligence aggregation, file-system event monitoring, or related security product or service.

3.9 **Use any name, mark, logo, or brand element** of Mythodikal Anti-Virus, or the Licensor (including the "M" glyph and the wordmark) without separate written permission, except as required for the limited attribution permitted in Section 2.3.

3.10 **Use the Software in any way** that is unlawful in Your jurisdiction or that violates the rights of any third party, including any export-control regulations applicable to security software.

3.11 **Circumvent or attempt to circumvent any technical protection measure** in the Software, including license-key validation routines and signed-update verification routines.

---

## 4. No Warranty

THE SOFTWARE IS PROVIDED "AS IS" AND "WITH ALL FAULTS," WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING WITHOUT LIMITATION ANY WARRANTY OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, NON-INFRINGEMENT, ACCURACY, COMPLETENESS, OR THAT THE SOFTWARE WILL DETECT OR PREVENT ANY MALWARE, VIRUS, OR OTHER UNDESIRABLE COMPUTER PROGRAM. ANTI-VIRUS SOFTWARE IS INHERENTLY IMPERFECT AND THE LICENSOR EXPRESSLY DISCLAIMS ANY GUARANTEE OF SECURITY OUTCOMES.

YOU BEAR THE ENTIRE RISK ARISING OUT OF THE USE OR PERFORMANCE OF THE SOFTWARE. IF THE SOFTWARE PROVES DEFECTIVE, YOU ASSUME THE COST OF ALL NECESSARY SERVICING, REPAIR, OR CORRECTION.

---

## 5. Limitation of Liability

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT WILL THE LICENSOR BE LIABLE TO YOU OR ANY THIRD PARTY FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, CONSEQUENTIAL, EXEMPLARY, OR PUNITIVE DAMAGES — INCLUDING BUT NOT LIMITED TO LOST PROFITS, LOST DATA, BUSINESS INTERRUPTION, COST OF SUBSTITUTE GOODS OR SERVICES, OR DAMAGES ARISING FROM A FAILURE OF THE SOFTWARE TO DETECT OR PREVENT MALWARE — REGARDLESS OF THE LEGAL THEORY ON WHICH THE CLAIM IS BASED, EVEN IF THE LICENSOR HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGES.

THE LICENSOR'S TOTAL CUMULATIVE LIABILITY ARISING OUT OF OR RELATED TO THIS LICENSE OR THE SOFTWARE WILL NOT EXCEED THE GREATER OF (A) THE TOTAL AMOUNT YOU PAID TO THE LICENSOR FOR THE SOFTWARE IN THE TWELVE MONTHS PRECEDING THE EVENT GIVING RISE TO LIABILITY OR (B) ONE U.S. DOLLAR.

---

## 6. Submissions

6.1 **Submissions you provide.** If You provide the Licensor with any feedback, suggestions, ideas, bug reports, security disclosures, code suggestions, sample data, translations, or other input (each a "Submission"), You hereby grant the Licensor a perpetual, irrevocable, worldwide, royalty-free, fully-paid-up, sublicensable, transferable license to use, reproduce, modify, distribute, prepare derivative works of, and exploit the Submission for any purpose, including incorporation into the Software.

6.2 **No obligation.** The Licensor is under no obligation to use, acknowledge, or compensate You for any Submission. Acknowledgment in `THIRD-PARTY-DATA.md`, `CONTRIBUTORS.md`, or release notes is at the Licensor's sole discretion.

6.3 **Security-disclosure incentives.** Notwithstanding Section 6.2, the Licensor maintains a vulnerability hall-of-fame and may, at its sole discretion, offer monetary rewards or complimentary Pro licenses for high-severity, responsibly-disclosed vulnerabilities, per the policy in `SECURITY.md`.

---

## 7. Third-Party Components

The Software depends on third-party components that are governed by their own licenses. The list of such components and their licenses is published in `THIRD-PARTY-DATA.md` and is also discoverable via `cargo deny check` in the project repository. Nothing in this license grants You any rights in or to those third-party components beyond what their respective licenses allow.

---

## 8. Trademark

"Mythodikal Anti-Virus," "Mythkernel,"," the "M" glyph, and the Mythodikal wordmark are unregistered trademarks of the Licensor. Nothing in this license grants You any right to use any of these marks except as expressly permitted in Section 2.3 (limited attribution).

---

## 9. Termination

9.1 **Automatic termination.** Your rights under this license terminate automatically and without notice upon any breach by You of Sections 3 (Prohibited Activities) or 8 (Trademark). Upon termination, You shall immediately: (a) cease all use of the Software; (b) delete all copies of the Software in Your possession or control, including any local clones, backups, derivative works prepared under Section 2.2, and Compiled Binaries derived from the Software; and (c) certify the deletion in writing if requested by the Licensor.

9.2 **Termination by Licensor.** The Licensor may terminate Your rights under this license at any time, in its sole discretion, with or without cause, by removing public access to the Software repository, by relicensing the Software under different terms, or by sending written notice to You.

9.3 **Survival.** Sections 4, 5, 6, 8, 9, 10, and 11 survive termination of this license.

---

## 10. Governing Law and Disputes

10.1 This license is governed by the laws of the State of Delaware, United States of America, without regard to conflict-of-laws principles.

10.2 Any dispute arising out of or related to this license or the Software shall be brought exclusively in the state or federal courts located in Delaware, and You consent to personal jurisdiction in those courts. Notwithstanding the foregoing, the Licensor may seek injunctive or equitable relief in any court of competent jurisdiction to protect intellectual property rights.

10.3 If any provision of this license is held to be unenforceable, that provision shall be modified to the minimum extent necessary to make it enforceable, and the remaining provisions shall remain in full force and effect.

---

## 11. Miscellaneous

11.1 **Entire agreement.** This license constitutes the entire agreement between You and the Licensor regarding the Software and supersedes all prior or contemporaneous communications.

11.2 **No waiver.** No failure or delay by the Licensor in exercising any right under this license shall operate as a waiver of that right.

11.3 **Assignment.** You may not assign this license. The Licensor may freely assign this license.

11.4 **Notices.** Notices to the Licensor shall be sent to `mythodikalone@gmail.com`. Notices to You may be made via the email address associated with Your GitHub account, the email You provided to the Licensor, or — if those are unavailable — by a public announcement on the project repository.

11.5 **Updates to this license.** The Licensor may publish revised versions of this license. Each version will carry a distinct version identifier (e.g., `LicenseRef-MythodikalARR-1.0`, `…-1.1`). Your use of the Software is governed by the version of this license in effect at the time You obtain or refresh Your local copy. If You disagree with a revised version, Your sole remedy is to stop using the Software and delete Your local copies as described in Section 9.1.

11.6 **No partnership.** Nothing in this license creates a partnership, joint venture, agency, employment, or other formal relationship between You and the Licensor.

11.7 **English controls.** This license is written in English. Any translation is provided for convenience only; in the event of any inconsistency, the English text controls.

---

## 12. Custom Commercial Licenses

If You wish to:

- embed the Software in another product;
- redistribute Compiled Binaries to Your customers;
- use the Software to provide a managed service;
- create a derivative work for sale;
- include the Software in an OEM bundle;

then You must contact the Licensor at `mythodikalone@gmail.com` for a separate, written commercial license. The Licensor is reachable and reasonable. Custom arrangements can be negotiated in good faith. Don't take what is not given.

---

## 13. Contact

- General licensing inquiries: `mythodikalone@gmail.com`
- Security disclosures: `mythodikalone@gmail.com`
- Maintainer: Mike Weaver, `mythodikalone@gmail.com`

---

*This license is the operative legal text governing the source repository "mythodikal-av." It is intentionally conservative because Mythodikal Anti-Virus is a security product and the integrity of its source matters. Source-visibility is a gift from the Licensor to the security community; the gift is bounded by this document.*

— *Last revised: 2026-05-09. License version: LicenseRef-MythodikalARR-1.0.*
