# Assumptions and unresolved dependencies

- Preserve the current working tree, requirement documents, public dataset and design references. Do not move source into legacy directories.
- Public samples are regression/calibration data, never rule lookup keys or execution input.
- Optional ML/SLM stays disabled until its adoption gate passes. No hosted model calls or model-generated training examples.
- Risk scores describe severity, not calibrated probabilities.
- Local checks can be run now; hosted CI results cannot be claimed without a hosted run.
- Azure CLI and Docker are absent in this environment. No Azure subscription/resource group or Supabase project has been provided. Cloud deployment gate remains pending; clarification requested.
- Organizer controlled pair is unavailable; only explicitly labelled harmless marker placeholders may eventually be executed for development proof.
- Existing dependencies are inventoried from installed metadata. ApexCharts distribution eligibility is unresolved; its custom licence must not be described as MIT.
- Significant decisions cite provided documents and are marked source-unverified until authoritative sources are independently checked.
