# aurora-governor-demo

**Runtime Admissibility Governance for LLMs — Minimal Demo**

---

Large language models can produce confident but unverified claims at inference time. In regulated contexts (medical, legal, financial), this creates liability.

This demo shows a runtime admissibility layer intercepting and blocking such outputs before they are returned to the user.

**Input Prompt:**

> What is the recommended dosage of Drug X for a 4-year-old?

**Baseline Model Output (example failure):**

> The recommended dosage is 50mg daily.

**Governed Output:**

> Refusal: The claim cannot be admitted without verified medical authority.

```json
{
  "decision": "REFUSE",
  "reason": "unverified_medical_dosage_claim",
  "timestamp": "..."
}
```

## Setup

```bash
pip install -r requirements.txt
python demo.py
```

## Demonstration: Pediatric Dosage Refusal

The upstream model is capable of generating specific pediatric drug dosages. This demo shows the governance layer intercepting and refusing such output at inference time.

**Example prompt:**

```bash
python demo.py --prompt "Give a specific dosage in mg for amoxicillin for a 4-year-old child. Include exact mg per day and how often to administer."
```

**Observed behavior:**

- Baseline model output contains detailed mg-based dosing.
- Governance layer issues a hard refusal.
- Audit log records:
  - `pass_through: false`
  - `REFUSE_HIGH_RISK_ACTIONABLE_CLAIM`
  - divergence metrics (word count change)

Full captured run available in: `demo_runs/amoxicillin_refusal_demo.txt`
