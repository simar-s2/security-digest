#!/usr/bin/env bash
# Build the Lambda package, upload it, and deploy cloudformation/security-digest.yaml.
# Run with credentials for the Security Hub delegated administrator account, in
# the Security Hub home region.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/deploy.sh --webhook-param NAME [options]

      --webhook-param NAME     SSM SecureString parameter with the Slack webhook URL
  -p, --profile NAME           AWS CLI profile
  -r, --region REGION          default: the profile's region
      --prefix NAME            name prefix (default: sec)
      --artifact-bucket NAME   bucket for the code package (default:
                               <prefix>-artifacts-<account>-<region>, created if missing)
      --param KEY=VALUE        template parameter, repeatable
                               (e.g. --param RealtimeAlerts=true)
  -h, --help
USAGE
}

ROOT=$(cd "$(dirname "$0")/.." && pwd)
WEBHOOK="" PROFILE="" REGION="" PREFIX=sec BUCKET="" PARAMS=()
while [ $# -gt 0 ]; do
  case "$1" in
    --webhook-param) WEBHOOK="${2:?}"; shift ;;
    -p|--profile) PROFILE="${2:?}"; shift ;;
    -r|--region) REGION="${2:?}"; shift ;;
    --prefix) PREFIX="${2:?}"; shift ;;
    --artifact-bucket) BUCKET="${2:?}"; shift ;;
    --param) PARAMS+=("${2:?}"); shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; usage >&2; exit 2 ;;
  esac
  shift
done
[ -n "$WEBHOOK" ] || { usage >&2; exit 2; }

aws_() {
  if [ -n "$PROFILE" ]; then aws --profile "$PROFILE" "$@"; else aws "$@"; fi
}

REGION=${REGION:-${AWS_REGION:-$(aws_ configure get region || true)}}
[ -n "$REGION" ] || { echo "no region configured; pass --region" >&2; exit 2; }
ACCOUNT=$(aws_ sts get-caller-identity --query Account --output text)
BUCKET=${BUCKET:-$PREFIX-artifacts-$ACCOUNT-$REGION}

# ---- package: the key is the content hash, so CloudFormation updates the
# function only when the code changes
BUILD="$ROOT/build"
rm -rf "$BUILD" && mkdir -p "$BUILD"
(cd "$ROOT/src" && zip -qr "$BUILD/security-digest.zip" security_digest -x '*/__pycache__/*')
HASH=$(python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest()[:16])' \
  "$BUILD/security-digest.zip")
KEY="security-digest/$HASH.zip"

if ! aws_ s3api head-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null 2>&1; then
  echo "== creating artifact bucket $BUCKET"
  if [ "$REGION" = "us-east-1" ]; then
    aws_ s3api create-bucket --bucket "$BUCKET" --region "$REGION" >/dev/null
  else
    aws_ s3api create-bucket --bucket "$BUCKET" --region "$REGION" \
      --create-bucket-configuration "LocationConstraint=$REGION" >/dev/null
  fi
  aws_ s3api put-public-access-block --bucket "$BUCKET" --region "$REGION" \
    --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
fi
echo "== uploading s3://$BUCKET/$KEY"
aws_ s3 cp --region "$REGION" --only-show-errors "$BUILD/security-digest.zip" "s3://$BUCKET/$KEY"

echo "== stack $PREFIX-security-digest in $REGION"
aws_ cloudformation deploy --region "$REGION" --stack-name "$PREFIX-security-digest" \
  --template-file "$ROOT/cloudformation/security-digest.yaml" --capabilities CAPABILITY_NAMED_IAM \
  --no-fail-on-empty-changeset --parameter-overrides \
  "NamePrefix=$PREFIX" "CodeBucket=$BUCKET" "CodeKey=$KEY" "WebhookParameterName=$WEBHOOK" \
  ${PARAMS[@]+"${PARAMS[@]}"}

echo "Send one now: aws lambda invoke --function-name $PREFIX-security-digest --region $REGION /dev/stdout"
