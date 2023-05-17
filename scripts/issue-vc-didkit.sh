#!/bin/sh
# This is a shell script using DIDKit for key generation and
# credential issuance. The credentials contain a UK home address.
# The script is based on example.sh

# Exit if any command in the script fails.
set -e

# Allow issuing using a DID method other than did:key
did_method=${DID_METHOD:-key}
# More info about did:key: https://w3c-ccg.github.io/did-method-key/

# Allow setting proof format using environmental variables.
proof_format=${PROOF_FORMAT:-ldp}
vc_proof_format=${VC_PROOF_FORMAT:-$proof_format}
vp_proof_format=${VP_PROOF_FORMAT:-$proof_format}

# Pretty-print JSON using jq or json_pp if available.
print_json() {
	file=${1?file}
	if command -v jq >/dev/null 2>&1; then
		jq . "$file" || cat "$file"
	elif command -v json_pp >/dev/null 2>&1; then
		json_pp < "$file" || cat "$file"
	else
		cat "$file"
	fi
}

# Run the rest of this script in its source directory.
cd "$(dirname "$0")"

# Build the didkit CLI program
cargo build -p didkit-cli

# Adjust $PATH to include the didkit executable.
export PATH="$PWD/../../target/debug:$PATH"

# Create a ed25119 keypair if needed.
if [ -e key.jwk ]; then
	echo 'Using existing keypair.'
else
	didkit generate-ed25519-key > key.jwk
	echo 'Generated keypair.'
fi
echo

# Get the keypair's DID.
did=$(didkit key-to-did "$did_method" -k key.jwk)
printf 'DID: %s\n\n' "$did"

# Get verificationMethod for keypair.
# This is used to identify the key in linked data proofs.
verification_method=$(didkit key-to-verification-method "$did_method" -k key.jwk)
printf 'verificationMethod: %s\n\n' "$verification_method"

# {
# 	"@context": "https://www.w3.org/2018/credentials/v1",
# 	"id": "http://example.org/credentials/3731",
# 	"type": ["VerifiableCredential"],
# 	"issuer": "$did",
# 	"issuanceDate": "2020-08-19T21:41:50Z",
# 	"credentialSubject": {
# 		"id": "did:example:d23dd687a7dc6787646f2eb98d0",
# 		"type": "my name"
# 	}
# }

# {
#   "@context": ["https://www.w3.org/2018/credentials/v1", "https://schema.org/"],
#   "id": "http://example.edu/credentials/332",
#   "type": ["VerifiableCredential", "IdentityCredential"],
#   "issuer": "$did",
#   "issuanceDate": "2020-08-19T21:41:50Z",
#   "credentialSubject": {
#     "name": "J. Doe",
#     "address": {
#       "streetAddress": "10 Rue de Chose",
#       "postalCode": "98052",
#       "addressLocality": "Paris",
#       "addressCountry": "FR"
#     },
#     "birthDate": "1989-03-15"
#   }
# }



# Prepare credential for issuing.
# In this example credential, the issuance date, id, and credential subject id
# are arbitrary. For more info about what these properties mean, see the
# Verifiable Credentials Data Model: https://w3c.github.io/vc-data-model/
# 

# Example credentials
# 1. multiple lines address
cat > credential-unsigned.jsonld <<EOF
{
  "@context": ["https://www.w3.org/2018/credentials/v1", "https://schema.org/"],
  "id": "http://example.edu/credentials/332",
  "type": ["VerifiableCredential", "IdentityCredential"],
  "issuer": "$did",
  "issuanceDate": "2020-08-19T21:41:50Z",
  "credentialSubject": {
    "name": "J. Doe",
    "address": {
      "streetAddress": "10 Main Street",
      "postalCode": "SE1 3WY",
      "addressLocality": "London",
      "addressCountry": "UK"
    },
    "birthDate": "1989-03-15"
  }
}
EOF

# 2. one line address
# cat > credential-unsigned.jsonld <<EOF
# {
#   "@context" : [
#     "https://www.w3.org/2018/credentials/v1",
#     "https://www.w3.org/2018/credentials/examples/v1", 
# 	"https://schema.org/"
#   ],
#   "id" : "http://example.edu/credentials/3732",
#   "type" : ["VerifiableCredential"],
#   "issuer" : "$did",
#   "holder" : {
#     "type" : "LawEnforcement",
#     "id" : "did:example:ebfeb1276e12ec21f712ebc6f1c"
#   },
#   "issuanceDate" : "2010-01-01T19:23:24Z",
#   "credentialSubject" : {
#     "id" : "did:example:ebfeb1f712ebc6f1c276e12ec21",
#     "name" : "Mr John Doe",
#     "address" : "10 Main Street, SE1 3WY, London, UK"
#   }
# }
# EOF

# Issue the verifiable credential.
# Ask didkit to issue a verifiable credential using the given keypair file,
# verification method, and proof purpose, passing the unsigned credential on
# standard input. DIDKit creates a linked data proof to add to the credential,
# and outputs the resulting newly-issued verifiable credential on standard
# output, which we save to a file.
print_json credential-unsigned.jsonld
didkit vc-issue-credential \
	-k key.jwk \
	-f "$vc_proof_format" \
	< credential-unsigned.jsonld \
	> credential-signed
echo 'Issued verifiable credential:'
if [ "$vc_proof_format" = jwt ]; then
	cat credential-signed
else
	print_json credential-signed
fi
echo
