# 005 Inventory licences before adding components

Status: accepted    Source status: unverified

Decision: Record installed component metadata and flag conditional licences explicitly.

Why: Existing ApexCharts packages use custom terms. No public distribution eligibility is inferred. New parsers/models require verified licences before adoption.

Alternatives rejected: Assume every npm dependency is MIT: rejected.

Evidence: initial evaluation in docs/reports/initial-evaluation.json; no comparative optimization measurement yet.

Sources: prd.md §18; installed apexcharts/LICENSE.md; react-apexcharts/LICENSE.
