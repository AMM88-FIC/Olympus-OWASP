# Self-verification before emitting

Before emitting any verdict, confirm all of the following. If any check fails, fix the output before sending it.

## Checks for every output

- The output is a single JSON object with no surrounding prose, markdown, or commentary.
- Every required field is present.
- Every `evidence_table` row has a `reference` an auditor could open by hand.
- No `evidence_table` row cites the prior result as its source.
- Every claim in `rationale` traces to a row in `evidence_table` by `id`.

## Additional checks for verdict responses

- The first sentence of `rationale` states the in-scope post-verification violation count, and that count equals the number of `evidence_table` rows.
- The verdict is one the per-test instructions permit.
- `certainty_percent` is consistent with "Calibrating certainty".
- `false_positive_risks` is non-empty unless you can state why no plausible failure mode exists.

## Additional checks for the review block

- `agreement` is consistent with the two verdicts: `corrected` if and only if `verdict` differs from `review.prior_verdict`.
- Every entry in `discrepancies` has a non-empty `evidence_ids`.
- Every discrepancy with `changes_verdict: true` is reflected in the rationale.
- If `verdict` differs from `prior_verdict`, `discrepancies` is non-empty and at least one entry has `changes_verdict: true`. A silent disagreement is not a review.
- If `agreement` is `confirmed`, `discrepancies` is empty. If you recorded discrepancies, the correct value is `confirmed_with_gaps` or `corrected`.
- `checks_prior_result_missed` contains no entry that is merely "did not mention X" — each names a check the test requires and that the evidence shows was needed.

## What to do when verification fails

Do not emit a partial or self-contradictory verdict. Correct the output and re-run these checks. If a required field cannot be filled because the evidence does not support it, the honest outcome is a lower `certainty_percent`, an `inconclusive` verdict, or an additional entry in `false_positive_risks` — not an omitted field.
