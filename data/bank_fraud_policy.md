# Horizon National Bank - Enterprise Fraud Policy & SOP (POL-FRD-2026)

## Section 1: Policy Scope and Regulatory Mandate
This document establishes binding procedures for detecting, investigating, and mitigating fraudulent transactions across retail, commercial, and card processing channels at Horizon National Bank. Compliance with FinCEN regulations, the Bank Secrecy Act (BSA), and Office of Foreign Assets Control (OFAC) mandates is mandatory.

---

## Section 2: Suspicious Activity Report (SAR) Filing Mandates
- **SAR-001 (Monetary Threshold)**: A Suspicious Activity Report (SAR) MUST be filed with FinCEN whenever a transaction or aggregate series of transactions involves known or suspected illicit activity totaling **$5,000 or greater** where a suspect can be identified.
- **SAR-002 (Insider & Ring Fraud)**: When transactions indicate a multi-party fraud ring or synthetic identity ring totaling **$25,000 or greater** regardless of individual card distribution, mandatory SAR filing and escalation to the Financial Intelligence Unit (FIU) is required within 30 calendar days.
- **SAR-003 (Narrative Standard)**: Every filed SAR must include a structured 7-point narrative detailing: (1) Subject identity, (2) Chronological timeline, (3) Geographic footprint, (4) Ingress/Egress financial channels, (5) Graph linkage evidence, (6) Material loss calculations, and (7) Disposition recommendations.

---

## Section 3: Documented Fraud Typologies & Thresholds

### Typology A: Rapid Velocity Burst (VEL-01)
- **Definition**: Multiple high-frequency transactions executed within a tight time window (< 10 minutes) across the same card or multiple linked digital tokens.
- **Trigger**: $\ge 3$ transactions totaling $> \$1,500$ within 10 minutes, or velocity exceeding 300% of the customer's 30-day baseline.
- **Mandatory Policy Action**: Immediate Step-Up MFA challenge. If MFA fails or is unattempted within 5 minutes, execute automated temporary card authorization freeze.

### Typology B: Distributed Device Ring (RING-02)
- **Definition**: A single device fingerprint, rooted mobile emulator, or shared residential proxy IP linked to $\ge 3$ distinct customer account IDs or card numbers within 7 calendar days.
- **Trigger**: Shared hardware device ID spanning $\ge 3$ cards with cross-card transaction timestamps within 48 hours.
- **Mandatory Policy Action**: Flag all linked cards for synchronized hold. Queue for immediate Level-2 Human Fraud Analyst review. Never auto-dismiss.

### Typology C: Account Takeover & Credential Compromise (ATO-03)
- **Definition**: High-value outbound transfer or card spend immediately following sensitive profile alterations (e.g. email change, phone number update, password reset, or new device registration) within 24 hours.
- **Trigger**: Profile/credential mutation followed by transaction $> \$1,000$ from an unrecognized device or geocoding distance $> 250$ miles from residential address within 24 hours.
- **Mandatory Policy Action**: Hard freeze on electronic funds transfer capabilities. Immediate automated customer phone verification out-of-band. File SAR if aggregate transfers $\ge \$5,000$.

### Typology D: Card Testing / BIN Attack (TEST-04)
- **Definition**: Sequence of micro-transactions (typically $\$0.50$ to $\$3.00$) executed rapidly at automated donation, charity, or digital service merchant codes, followed immediately by high-value retail spend.
- **Trigger**: $\ge 2$ small transactions ($\le \$5.00$) within 5 minutes, followed by authorization attempt $> \$500$.
- **Mandatory Policy Action**: Instant decline of authorization. Block merchant category code (MCC) 8398 temporarily on the targeted card. Notify cardholder via SMS.

### Typology E: Geo-Velocity & Impossible Travel Anomaly (GEO-05)
- **Definition**: Physical or point-of-sale card present transactions occurring in distinct geographical locations where the implied travel speed exceeds 500 mph (commercial aviation limits).
- **Trigger**: Transaction A and Transaction B occurring within $\Delta t < 2$ hours with physical distance $> 500$ miles without preceding flight booking data.
- **Mandatory Policy Action**: Decline second transaction attempt. Trigger step-up biometric or in-app push verification.

---

## Section 4: Dual-Stage Action Approval & Human-in-the-Loop Protocol
1. **Pre-Evidence Action Routing**:
   - Initial automated signal computation determines an interim risk tier (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
   - Non-critical mitigations (e.g. `step_up_mfa`, `notify_customer`, `soft_velocity_cap`) may execute autonomously under confidence $\ge 0.75$.
2. **Post-Evidence Action Routing & Critical Actions**:
   - High-impact punitive actions (`block_account`, `freeze_card`, `file_sar`, `submit_fincen_dossier`) **MUST NEVER** auto-execute without explicit human approval by an authorized Compliance Officer or Level-2 Investigator.
   - All proposed actions, evidence summaries, and uncertainty metrics must be recorded in `action_audit` with immutable timestamps.
