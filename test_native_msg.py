#!/usr/bin/env python3
"""Test script for tpm-fido Native Messaging protocol."""

import json
import base64
import os

def main():
    # Create a test request
    challenge = base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
    user_id = base64.urlsafe_b64encode(os.urandom(16)).decode('utf-8').rstrip('=')

    create_request = {
        "type": "create",
        "requestId": "test-123",
        "origin": "https://example.com",
        "options": {
            "challenge": challenge,
            "rp": {
                "id": "example.com",
                "name": "Example"
            },
            "user": {
                "id": user_id,
                "name": "test@example.com",
                "displayName": "Test User"
            },
            "pubKeyCredParams": [
                {"type": "public-key", "alg": -7}
            ],
            "authenticatorSelection": {
                "residentKey": "required"
            },
            "extensions": {
                "prf": {
                    "eval": {
                        "first": base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')
                    }
                }
            }
        }
    }

    print(f"Test request: {json.dumps(create_request, indent=2)}")
    print("\nNote: This test will wait for fingerprint verification.")
    print("To test without fingerprint, you need a mock fprintd-verify program to succeed.")
    print("\nTo run the test:")
    print("  ./tpm-fido --backend=memory")
    print("\nThen paste the request above (as a Native Messaging message)")

if __name__ == "__main__":
    main()
