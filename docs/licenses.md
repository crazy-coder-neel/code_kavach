# Third-party register

The machine-readable [inventory](licenses.json) records installed versions, declared licences and metadata provenance for direct and transitive packages. Regenerate with `backend/.venv/bin/python scripts/license-inventory.py`. Metadata is not a grant of rights or proof that every bundled asset has been reviewed. No new runtime library was introduced in Phase 0.

| Component | Use | Installed licence evidence | Distribution status |
|---|---|---|---|
| Python standard library | Static parsing, hashing, networking utilities | PSF; Python distribution | Existing runtime |
| FastAPI / Pydantic | HTTP / validation | MIT; installed metadata | Existing runtime |
| Uvicorn / Starlette | ASGI | BSD-3-Clause; installed metadata | Existing runtime |
| React / React DOM / React Router | Console | MIT; installed package metadata | Existing runtime |
| Monaco React | Editor adapter | MIT; installed package metadata | Existing runtime |
| Lucide React | Icons | ISC; installed metadata | Existing runtime; README previously misstated MIT |
| ApexCharts / React ApexCharts | Console charts | Custom community/commercial/OEM terms; installed LICENSE.md / LICENSE | Rights/eligibility unresolved; do not publish under an assumed MIT grant. Replace in frontend phase or establish appropriate rights. |
| Vite / Tailwind / associated plugins / tsx / type packages | Frontend tooling | MIT; installed metadata | Existing development dependencies |
| TypeScript | Type checks | Apache-2.0; installed metadata | Existing development dependency |
| HTTPX | Contract tests | BSD-3-Clause; installed metadata | Existing test dependency, now in requirements-dev.txt |
| GitHub checkout/setup-node/setup-python/upload-artifact actions | Hosted CI | Source not independently reviewed in this run | Workflow prepared; hosted execution not run |
| Bun / setup-bun action | Lockfile installation in hosted CI | Source not independently reviewed in this run | Existing package manager; hosted execution not run |

No pretrained model, third-party security detector, public training corpus, SQL/shell parser package, or Supabase client has been added. The organizer-provided dataset is retained unchanged; its licence is not inferred.
