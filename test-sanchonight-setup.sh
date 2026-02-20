#!/usr/bin/env bash
set -e

# Test script for SanchoNight federated network setup
# Demonstrates the workflow from the README:
# - 3 validators generate keys independently
# - 2 TA members generate governance keys
# - 3 Council members generate governance keys
# - Coordinator aggregates all keys into genesis

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR=$(mktemp -d)
echo "Test directory: $TEST_DIR"

# Build the CLI using nix
echo "Building midnight-cli..."
cd "$SCRIPT_DIR"
nix develop -c cargo build --release 2>&1 | tail -1
CLI="$SCRIPT_DIR/target/release/midnight-cli"

cd "$TEST_DIR"

# Step 1: Validators generate keys independently
echo ""
echo "=== Step 1: Validators Generate Keys ==="

$CLI validator generate \
  --mnemonic "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art" \
  --output validator1-keys.json

$CLI validator generate \
  --mnemonic "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote" \
  --output validator2-keys.json

$CLI validator generate \
  --mnemonic "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless" \
  --output validator3-keys.json

echo "✓ Generated 3 validator key sets"

# Step 2: TA members generate governance keys
echo ""
echo "=== Step 2: TA Members Generate Governance Keys ==="

$CLI governance generate \
  --mnemonic "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog" \
  --output ta1-governance.json

$CLI governance generate \
  --mnemonic "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length" \
  --output ta2-governance.json

echo "✓ Generated 2 TA governance keys"

# Step 3: Council members generate governance keys
echo ""
echo "=== Step 3: Council Members Generate Governance Keys ==="

$CLI governance generate \
  --mnemonic "scheme spot photo card baby mountain device kick cradle pact join borrow" \
  --output council1-governance.json

$CLI governance generate \
  --mnemonic "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave" \
  --output council2-governance.json

$CLI governance generate \
  --mnemonic "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside" \
  --output council3-governance.json

echo "✓ Generated 3 Council governance keys"

# Step 4: Coordinator aggregates validators into single JSON
echo ""
echo "=== Step 4: Coordinator Aggregates Keys ==="

# Combine validators into array
jq -s '.' validator1-keys.json validator2-keys.json validator3-keys.json > validators-aggregated.json

# Combine all governance (TA + Council) into array
jq -s '.' ta1-governance.json ta2-governance.json council1-governance.json council2-governance.json council3-governance.json > governance-aggregated.json

echo "✓ Aggregated validator and governance keys"

# Step 5: Generate genesis configuration
echo ""
echo "=== Step 5: Generate Genesis Configuration ==="

GARBAGE_POLICY_ID="deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

$CLI genesis init \
  --validators validators-aggregated.json \
  --governance governance-aggregated.json \
  --night-policy-id "$GARBAGE_POLICY_ID" \
  --chain-id sanchonight-test \
  --output genesis.json

echo "✓ Generated genesis configuration"

# Step 6: Verify the genesis configuration
echo ""
echo "=== Step 6: Verify Genesis Configuration ==="

# Check that we have 3 validators
VALIDATOR_COUNT=$(jq '.validators | length' genesis.json)
if [ "$VALIDATOR_COUNT" != "3" ]; then
  echo "❌ Expected 3 validators, got $VALIDATOR_COUNT"
  exit 1
fi
echo "✓ Genesis has 3 validators"

# Check that we have 5 governance members (2 TA + 3 Council)
COUNCIL_COUNT=$(jq '.governance.council | length' genesis.json)
if [ "$COUNCIL_COUNT" != "5" ]; then
  echo "❌ Expected 5 council members, got $COUNCIL_COUNT"
  exit 1
fi
echo "✓ Genesis has 5 council members"

TC_COUNT=$(jq '.governance.technical_committee | length' genesis.json)
if [ "$TC_COUNT" != "5" ]; then
  echo "❌ Expected 5 technical committee members, got $TC_COUNT"
  exit 1
fi
echo "✓ Genesis has 5 technical committee members"

# Check policy ID
POLICY_ID=$(jq -r '.night_token.policy_id' genesis.json)
if [ "$POLICY_ID" != "$GARBAGE_POLICY_ID" ]; then
  echo "❌ Expected policy ID $GARBAGE_POLICY_ID, got $POLICY_ID"
  exit 1
fi
echo "✓ Genesis has correct $NIGHT policy ID"

# Check chain ID
CHAIN_ID=$(jq -r '.chain_id' genesis.json)
if [ "$CHAIN_ID" != "sanchonight-test" ]; then
  echo "❌ Expected chain ID sanchonight-test, got $CHAIN_ID"
  exit 1
fi
echo "✓ Genesis has correct chain ID"

# Display final genesis
echo ""
echo "=== Final Genesis Configuration ==="
jq '.' genesis.json

# Summary
echo ""
echo "=== Test Summary ==="
echo "✓ 3 validators generated keys independently"
echo "✓ 2 TA members generated governance keys"
echo "✓ 3 Council members generated governance keys"
echo "✓ Coordinator aggregated keys into genesis"
echo "✓ Genesis configuration validated"
echo ""
echo "Test artifacts saved to: $TEST_DIR"
echo "Genesis file: $TEST_DIR/genesis.json"
