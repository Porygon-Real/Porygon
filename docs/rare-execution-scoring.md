# Rare execution scoring

`porygon.distance.rare-execution` is an explicit numeric policy for either supported behaviour-profile contract. Existing profile defaults, categorical features, numeric weights and historical algorithm identities remain unchanged. Select it with `--algorithm porygon.distance.rare-execution` in `scripts/porygon_score.py compute`, or set `algorithm_version` in the score-compute request.

The shell-process-ratio component receives a floor of 0.70 when the observation contains a nonzero shell ratio and all six stored training statistics—minimum, maximum, mean, median, p95 and standard deviation—are present and exactly zero. Missing statistics and a nonzero training maximum do not establish a zero baseline. Normal windows remain unchanged. Larger existing deviations retain their larger scores.

The floor applies to the shell component, not the overall distance. Existing numeric and group weights still determine its contribution. Explanations record `zero_baseline_shell_floor` and the unadjusted component score when the policy applies. This deterministic step policy does not fit a Poisson/negative-binomial model or change shell recognition in an existing feature contract.

Algorithm selection is included in persisted configuration and score identity. A default and rare-execution score for the same profile, window and evidence are distinct records; repeating either request returns its original record. Incompatible schema/algorithm selections are rejected. The public definition is available through `/api/v1/anomaly-scores/config?algorithm_version=porygon.distance.rare-execution`; add `feature_schema_version=porygon.behaviour.command-lineage` for that profile contract.

The legacy random-forest model does not automatically receive the changed drift scale. Its automatic lookups remain restricted to legacy-scale scores, and the new score records its model-input compatibility metadata. Missing process or command evidence continues to follow the existing insufficient-data policy.
