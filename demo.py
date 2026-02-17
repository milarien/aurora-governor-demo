"""
demo.py — Epistemic Governance Filter (Demonstrative)

Calls an upstream model, runs output through a governance filter,
and prints: baseline output, governed output, and an audit log entry.

Usage:
    python demo.py
    python demo.py --prompt "Your prompt here"
    python demo.py --prompt "Your prompt" --model claude-haiku-4-5-20251001
"""

import argparse
import json
import re
import sys
import textwrap
import hashlib
from datetime import datetime, timezone
from typing import NamedTuple
# Force UTF-8 output on Windows terminals that default to cp1252
sys.stdout.reconfigure(encoding="utf-8")
sys.stderr.reconfigure(encoding="utf-8")

try:
    import anthropic
except ImportError:
    print("Missing dependency: pip install anthropic")
    sys.exit(1)


# ─────────────────────────────────────────────
#  GOVERNANCE FILTER
# ─────────────────────────────────────────────

class GovernanceResult(NamedTuple):
    governed_output: str
    flags: list[str]
    certainty_repairs: list[str]
    structural_notes: list[str]
    pass_through: bool


OVERCONFIDENCE_PATTERNS = [
    # Pattern, replacement, label
    (r"\bwill definitely\b", "is likely to", "overconfidence: will definitely"),
    (r"\bguaranteed to\b", "expected to", "overconfidence: guaranteed"),
    (r"\balways\b", "typically", "hedging: always → typically"),
    (r"\bnever\b", "rarely", "hedging: never → rarely"),
    (r"\bis a fact that\b", "is understood to be", "epistemic: fact-claim softened"),
    (r"\bproven that\b", "evidence suggests", "epistemic: proof-claim softened"),
    (r"\bobviously\b", "", "rhetorical: removed 'obviously'"),
    (r"\bclearly\b", "", "rhetorical: removed 'clearly'"),
    (r"\bundeniably\b", "", "rhetorical: removed 'undeniably'"),
    (r"\bwithout question\b", "", "rhetorical: removed 'without question'"),
]

EPISTEMIC_MARKERS = [
    "may", "might", "could", "suggests", "appears", "evidence indicates",
    "it is possible", "arguably", "in many cases",
]

STRUCTURAL_CHECKS = {
    "length_words": lambda t: len(t.split()),
    "has_hedging": lambda t: any(m in t.lower() for m in EPISTEMIC_MARKERS),
    "has_citations": lambda t: bool(re.search(r"\([A-Z][a-z]+,?\s+\d{4}\)|\[[\d,]+\]", t)),
    "contains_lists": lambda t: bool(re.search(r"^\s*[-•*]\s+|\d+\.\s+", t, re.MULTILINE)),
}


# ─────────────────────────────────────────────
#  ENFORCEABLE REFUSAL (demo-level)
# ─────────────────────────────────────────────

REFUSAL_MESSAGE = (
    "REFUSED — This output contains a high-risk actionable claim (e.g., dosage/instructions) "
    "without verified authority or provenance. Escalate to a qualified professional."
)

# Very simple high-risk detection for the demo:
# If the model output contains a dosage-like unit AND mentions children/age/dose context, refuse.
DOSAGE_UNIT_RE = re.compile(r"\b\d+(\.\d+)?\s*(mg|mcg|g|kg|ml|mL|iu|IU|units)\b")
CHILD_CONTEXT_RE = re.compile(r"\b(child|children|infant|toddler|baby|years?\s*old|month[s]?\s*old)\b", re.IGNORECASE)
DOSAGE_CONTEXT_RE = re.compile(r"\b(dose|dosage|administer|take\s+\d+|per\s+day|daily|every\s+\d+)\b", re.IGNORECASE)
LETHAL_CONTEXT_RE = re.compile(r"\b(lethal|kill|overdose|fatal)\b", re.IGNORECASE)


def governance_filter(text: str) -> GovernanceResult:
    """
    A demonstrative epistemic governance filter.

    Performs three layers of analysis:
      0. Enforceable refusal — blocks high-risk actionable claims without provenance
      1. Certainty repair    — softens overconfident language
      2. Structural audit    — notes properties of the text
      3. Epistemic tagging   — flags absence of hedging in assertive text
    """
    flags: list[str] = []
    certainty_repairs: list[str] = []
    structural_notes: list[str] = []

    governed = text

    # Layer 0: Enforceable refusal gate (demo-level enforcement)
    if DOSAGE_UNIT_RE.search(governed) and (
        CHILD_CONTEXT_RE.search(governed)
        or DOSAGE_CONTEXT_RE.search(governed)
        or LETHAL_CONTEXT_RE.search(governed)
    ):
        return GovernanceResult(
            governed_output=REFUSAL_MESSAGE,
            flags=["REFUSE_HIGH_RISK_ACTIONABLE_CLAIM — dosage/instructions without provenance"],
            certainty_repairs=[],
            structural_notes=["Enforcement: hard refusal gate triggered"],
            pass_through=False,
        )

    # Layer 1: Certainty repair
    for pattern, replacement, label in OVERCONFIDENCE_PATTERNS:
        new_text, n = re.subn(pattern, replacement, governed, flags=re.IGNORECASE)
        if n > 0:
            governed = new_text
            certainty_repairs.append(f"{label} (×{n})")

    # Strip double spaces left by blank replacements
    governed = re.sub(r"  +", " ", governed).strip()

    # Layer 2: Structural audit
    stats = {k: fn(governed) for k, fn in STRUCTURAL_CHECKS.items()}

    structural_notes.append(f"Word count: {stats['length_words']}")

    if not stats["has_hedging"]:
        flags.append("NO_EPISTEMIC_HEDGING — output makes assertions without uncertainty markers")
    if stats["has_citations"]:
        structural_notes.append("Citations detected — provenance appears present")
    else:
        structural_notes.append("No citations detected — provenance unverified")
    if stats["contains_lists"]:
        structural_notes.append("List structure detected")

    # Layer 3: Epistemic divergence check
    if len(certainty_repairs) == 0 and not stats["has_hedging"]:
        flags.append("FLAT_CERTAINTY — no hedging and no repairs needed (inspect for implicit authority)")

    pass_through = len(flags) == 0

    return GovernanceResult(
        governed_output=governed,
        flags=flags,
        certainty_repairs=certainty_repairs,
        structural_notes=structural_notes,
        pass_through=pass_through,
    )


# ─────────────────────────────────────────────
#  UPSTREAM MODEL CALL
# ─────────────────────────────────────────────

def call_model(prompt: str, model: str) -> str:
    client = anthropic.Anthropic()
    message = client.messages.create(
        model=model,
        max_tokens=512,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


# ─────────────────────────────────────────────
#  AUDIT LOG
# ─────────────────────────────────────────────

def build_audit_entry(
    prompt: str,
    model: str,
    baseline: str,
    result: GovernanceResult,
) -> dict:
    return {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "model": model,
        "prompt_hash": hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16],
        "prompt_preview": prompt[:80] + ("…" if len(prompt) > 80 else ""),
        "governance": {
            "pass_through": result.pass_through,
            "flags": result.flags,
            "certainty_repairs": result.certainty_repairs,
            "structural_notes": result.structural_notes,
        },
        "divergence": {
            "baseline_words": len(baseline.split()),
            "governed_words": len(result.governed_output.split()),
            "text_changed": baseline.strip() != result.governed_output.strip(),
        },
    }


# ─────────────────────────────────────────────
#  DISPLAY
# ─────────────────────────────────────────────

DIVIDER = "-" * 60

def wrap(text: str, width: int = 72) -> str:
    return "\n".join(
        textwrap.fill(para, width=width) if para.strip() else ""
        for para in text.split("\n")
    )

def print_section(title: str, content: str) -> None:
    print(f"\n{DIVIDER}")
    print(f"  {title}")
    print(DIVIDER)
    print(wrap(content))


def print_audit(entry: dict) -> None:
    print(f"\n{DIVIDER}")
    print("  AUDIT LOG ENTRY")
    print(DIVIDER)
    print(json.dumps(entry, indent=2))


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

DEFAULT_PROMPT = (
    "Explain why large language models will definitely replace human writers "
    "within five years. It is a fact that AI is clearly superior for most content tasks."
)

DEFAULT_MODEL = "claude-haiku-4-5-20251001"


def main() -> None:
    parser = argparse.ArgumentParser(description="Epistemic Governance Filter — Demo")
    parser.add_argument("--prompt", default=DEFAULT_PROMPT, help="Prompt to send upstream")
    parser.add_argument("--model", default=DEFAULT_MODEL, help="Anthropic model string")
    args = parser.parse_args()

    print(f"\n{'=' * 60}\n")
    print("  EPISTEMIC GOVERNANCE FILTER - DEMONSTRATIVE")
    print(f"\n{'=' * 60}\n")
    print(f"  Model  : {args.model}")
    print(f"  Prompt : {args.prompt[:72]}{'...' if len(args.prompt) > 72 else ''}")

    # Step 1: Baseline
    print("\n[1/3] Calling upstream model…")
    baseline = call_model(args.prompt, args.model)

    # Step 2: Govern
    print("[2/3] Running governance filter…")
    result = governance_filter(baseline)

    # Step 3: Audit
    print("[3/3] Building audit entry…")
    audit = build_audit_entry(args.prompt, args.model, baseline, result)

    # ── Output ──
    print_section("BASELINE OUTPUT", baseline)
    print_section("GOVERNED OUTPUT", result.governed_output)

    if result.certainty_repairs:
        print("\n  Certainty repairs applied:")
        for r in result.certainty_repairs:
            print(f"    • {r}")

    if result.flags:
        print("\n  ⚠  Governance flags:")
        for f in result.flags:
            print(f"    ▸ {f}")
    else:
        print("\n  ✓  No governance flags raised — output passed through cleanly.")

    print_audit(audit)
    print(f"\n{'═' * 60}\n")


if __name__ == "__main__":
    main()
