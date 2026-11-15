"""Deterministic bounded software replay, separate from live sensor receipts."""
import argparse
import json
from pathlib import Path
from experiments.attacks.catalog import catalog, digest, SCOPE, START, END


def replay():
    from porygon_api.runtime_evidence import build_bundle
    from porygon_api.command_shapes import command_shape_counts
    document = catalog()
    results = []
    for case in document['cases']:
        try:
            bundle = build_bundle(case['events'], SCOPE, START, END, case['known_executables'],
                                  context={'events': case.get('context_events', []), 'status': 'complete'})
            actual = sorted({row['rule_id'] for row in bundle['findings']})
            passed = actual == case['expected_rules'] and not case.get('expected_error')
            result = dict(case_id=case['case_id'], label=case['label'], expected=case['expected_rules'],
                          actual=actual, software_assertion_passed=passed, bundle_hash=bundle['bundle_hash'],
                          event_ids=[e['event_id'] for e in case['events']], coverage=bundle['coverage'])
        except ValueError:
            result = dict(case_id=case['case_id'], label=case['label'], rejected=True,
                          software_assertion_passed=case.get('expected_error', False))
        results.append(result)
    commands = []
    for pair in document['command_pairs']:
        positive = dict(command_shape_counts(pair['positive']))
        control = dict(command_shape_counts(pair['control']))
        commands.append(dict(pair_id=pair['pair_id'], positive_shapes=positive, control_shapes=control,
                             distinguishable=positive != control, padding_counts=pair.get('padding_counts', []),
                             padding_observations=[{'benign_repetitions': count,
                                'positive_shape_mass_fraction': sum(positive.values())/(sum(positive.values())+count*sum(control.values()))}
                                for count in pair.get('padding_counts', [])]))
    return dict(catalog_sha256=digest(document), mode='software-fixtures', cases=results,
                command_observations=commands, live_capture_verified=False)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = replay()
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True)+'\n')
    return 0 if all(x['software_assertion_passed'] for x in result['cases']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
