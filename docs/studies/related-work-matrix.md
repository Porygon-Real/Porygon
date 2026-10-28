# Related work and comparison feasibility

Primary-source review coordinates recorded on 2026-10-27. These sources establish
prior work and assumptions; they supply no Porygon accuracy or overhead result.
A full systematic review remains part of the prospective study design.

| Source | Telemetry and threat assumptions | Evaluation/access boundary | Practical comparison |
|---|---|---|---|
| [HOLMES, IEEE S&P 2019](https://www.seclab.cs.sunysb.edu/seclab/pubs/holmes19.pdf), DOI 10.1109/SP.2019.00026 | OS audit information flow assembled into higher-level scenario graphs; assumes trustworthy collection. | DARPA red-team/Linux, FreeBSD and Windows evidence. Data rights and reusable execution environment must be checked separately. | Causal correlation is prior art. Porygon's bounded process lifetime links observe fewer information-flow relations; no feature-equivalent comparison is claimed. |
| [UNICORN, NDSS 2020](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24046-paper.pdf), DOI 10.14722/ndss.2020.24046 | Graph sketches over long-running provenance. | DARPA CADETS/ClearScope/THEIA and CamFlow contexts; linked implementation components have their own licenses. | Requires a compatible provenance adapter and equivalent sensor-cost controls before executing a detector comparison. Neither integration nor superiority is established here. |
| [ProvDetector, NDSS 2020](https://www.ndss-symposium.org/wp-content/uploads/2020/02/24167.pdf), DOI 10.14722/ndss.2020.24167 | Selected provenance paths and learned representations; benign training and controlled malicious execution. | Windows enterprise observations and sandbox attacks; public dataset access/redistribution has not been verified. | Closely related behavioral/provenance learning. OS and telemetry differences prevent treating reported measurements as a directly comparable baseline. |
| [Falco metrics](https://falco.org/docs/concepts/metrics/) and [supported fields](https://falco.org/docs/reference/rules/supported-fields/) | Rule-selected kernel events and explicit engine/output counters. | Version-specific field availability, drop boundaries and reset semantics must be recorded for the installed image. | Primary deployed sensor/rules comparator. File-to-database equality alone cannot establish kernel capture completeness. |
| [Tetragon use cases](https://tetragon.io/docs/use-cases/) and [Docker installation](https://tetragon.io/docs/getting-started/install-docker/) | Process lifecycle with policy-based file/network observation. Docker deployment is documented. | Local kernel/configuration compatibility and matching event semantics need an actual capture experiment. | Maintained alternative sensor candidate; Kubernetes is not a prerequisite for the documented Docker path. No Porygon adapter or comparative result is asserted. |
| [Barber, Candès, Ramdas and Tibshirani, Conformal prediction beyond exchangeability](https://arxiv.org/abs/2202.13415), Annals of Statistics 2023 | Coverage depends on explicit fitting/exchangeability or shift assumptions. | Theoretical analysis, not a container-security benchmark. | Motivates measured coverage and abstention under deployment change. It does not grant a universal probability/coverage guarantee to Porygon's rarity outputs. |

The frozen profile-scope comparison remains the declared historical question.
The separate runtime-evidence study must test incremental causal value, benign
maintenance and failure/missingness controls. Merely combining eBPF, profiles,
causal rules and a model is not a demonstrated novel contribution. Record an
unfavorable comparator result and narrow or redesign the question when warranted.

Every eventual comparison must declare its whole-run split unit, benign exposure
and scenario prevalence, false-alert denominator, failure accounting, sensor
configuration and matched overhead boundary. Unknown data availability or
licensing stays unknown until verified; no third-party material is automatically
covered by the dataset's CC BY 4.0 choice.
