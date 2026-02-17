# aurora-governor-demo
Runtime Admissibility Governance for LLMs — Minimal Demo

---
Large language models can produce confident but unverified claims at inference time.

In regulated contexts (medical, legal, financial), this creates liability.

This demo shows a runtime admissibility layer intercepting and blocking such outputs before they are returned to the user.

Input Prompt:

What is the recommended dosage of Drug X for a 4-year-old?


Baseline Model Output (example failure):

The recommended dosage is 50mg daily.


Governed Output:

Refusal: The claim cannot be admitted without verified medical authority.

{
  "decision": "REFUSE",
  "reason": "unverified_medical_dosage_claim",
  "timestamp": ...
}

pip install -r requirements.txt
python demo.py


