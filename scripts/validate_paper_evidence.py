"""Verify exact claim-to-result identities after offline replay; never invent claims."""
import argparse
import json
import math
from pathlib import Path
import sys
ROOT=Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:sys.path.insert(0,str(ROOT))
from experiments.confirmatory import replay,collection_conformance,confined,read_document
from experiments.artifacts import ArtifactError,sha256_file


def resolve(document,coordinate):
    if not isinstance(coordinate,str) or not coordinate or len(coordinate)>1024:raise ArtifactError('Bounded result coordinate required')
    value=document
    for token in coordinate.split('.'):
        if isinstance(value,list) and token.isdigit() and int(token)<len(value):value=value[int(token)]
        elif isinstance(value,dict) and token in value:value=value[token]
        else:raise ArtifactError('Claim metric coordinate does not exist')
    return value


def validate(run_dir):
    report=replay(run_dir);conformance=collection_conformance(run_dir)
    claims=read_document(confined(run_dir,'claim-results.json'))
    if claims.get('contract')!='porygon.claim-results' or not isinstance(claims.get('claims'),list) or not claims['claims']:
        raise ArtifactError('Explicit claim-to-result map required')
    identifiers=set()
    for claim in claims['claims']:
        if claim['claim_id'] in identifiers:raise ArtifactError('Duplicate claim identifier')
        identifiers.add(claim['claim_id'])
        if claim.get('status') not in ('supported','not-supported','not-evaluated'):raise ArtifactError('Explicit negative/unevaluated status required')
        path=confined(run_dir,claim['result_path'])
        if sha256_file(path)!=claim['result_sha256']:raise ArtifactError('Claim result hash mismatch')
        if claim['status']=='supported' and (not conformance['valid'] or report['collection_accounting']['failed_or_missing']):
            raise ArtifactError('Supported claims require complete validated measured accounting')
        if not claim.get('metric_coordinates') or not claim.get('scope_boundary'):raise ArtifactError('Metric coordinate and scope boundary required')
        document=read_document(path);metric=resolve(document,claim['metric_coordinates'])
        if claim['status']=='supported':
            if 'declared_value' not in claim or claim['declared_value']!=metric or metric is None:raise ArtifactError('Supported claim value differs from concrete measured result')
            if isinstance(metric,(int,float)) and not math.isfinite(metric):raise ArtifactError('Finite measured claim value required')
            denominators=claim.get('denominator_coordinates')
            if not isinstance(denominators,list) or not denominators:raise ArtifactError('Supported claim requires explicit independent-run denominators')
            for coordinate in denominators:
                count=resolve(document,coordinate)
                if type(count) is not int or count<1:raise ArtifactError('Claim denominator is missing or empty')
            comparison=resolve(document,claim.get('comparison_coordinate',''))
            if not isinstance(comparison,dict) or comparison.get('status')!='analysed' or comparison.get('decision',{}).get('h1_supported') is not True:
                raise ArtifactError('Supported comparative claim requires the matching complete prespecified decision')
        if claim.get('unsupported_completeness_claim') or claim.get('window_as_independent_unit'):
            raise ArtifactError('Capture completeness and independent-unit boundary violated')
    return {'valid':True,'claims':len(identifiers),'collection_complete':conformance['valid'],'scientific_claims_reviewed':all(row['status']!='not-evaluated' for row in claims['claims']),
        'scope':'hash links and recorded evidence; independent physical reproduction remains separate'}


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--run-dir',type=Path,required=True);args=parser.parse_args()
    try:result=validate(args.run_dir)
    except (ArtifactError,ValueError,KeyError,OSError):
        print(json.dumps({'valid':False,'reason':'missing, altered or unsupported evidence'}));return 1
    print(json.dumps(result));return 0


if __name__=='__main__':raise SystemExit(main())
