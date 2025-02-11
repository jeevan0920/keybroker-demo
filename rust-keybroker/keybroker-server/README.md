# Reference Values

## Arm CCA

The Arm CCA appraisal policy requires the user to provide one or more RIM values corresponding to known and trusted Realm workloads.

The reference values must be provided in a JSON file that conforms to the following CDDL grammar:

```cddl
start = {
  "reference-values": [ + b64-rim ]
}

b64-rim = text .b64c rim

rim = bytes .size 32
```

Note that the RIM values are Base64-encoded and that there must be at least one.

### Example

The following contains reference values for three trusted workloads:

```json
{
  "reference-values": [
    "MRMUq3NiA1DPdYg0rlxl2ejC3H/r5ufZZUu+hk4wDUk=",
    "q3N/r5ufZZUu+iAg0rlxl2ejC3HMRMUhk4wDUk1DPdY=",
    "UvZTSVUJ6IZtdtK0GEa5nueYxDcEJDa2vNHYL6RhQbs="
  ]
}
```

## Key Request APIs

The keybroker server supports two methods for requesting keys:

1. **Challenge-Response Attestation** (`/keys/v1/key/{keyid}`):
   - Traditional flow where the server issues a challenge that must be answered with attestation evidence
   - Requires two API calls: one to get the challenge and another to submit the evidence

2. **Passport-based Verification** (`/keys/v1/key/passport/{keyid}`):
   - Streamlined flow using a pre-generated attestation passport
   - Single API call where the passport is verified immediately
   - Returns the wrapped key directly if the passport is valid

### Mock mode

In "mock" mode, the keybroker server must be started using the following command line:

```sh
keybroker-server \
    --mock-challenge \
    --verbose \
    --reference-values <(echo '{ "reference-values": [ "MRMUq3NiA1DPdYg0rlxl2ejC3H/r5ufZZUu+hk4wDUk=" ] }')
```