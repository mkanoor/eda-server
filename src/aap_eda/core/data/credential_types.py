#  Copyright 2024 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.

from aap_eda.core import enums

CREDENTIAL_TYPES = [
    {
        "name": enums.DefaultCredentialType.SOURCE_CONTROL,
        "namespace": "scm",
        "kind": "scm",
        "inputs": {
            "fields": [
                {"id": "username", "label": "Username", "type": "string"},
                {
                    "id": "password",
                    "label": "Password",
                    "type": "string",
                    "secret": True,
                },
                {
                    "id": "ssh_key_data",
                    "label": "SCM Private Key",
                    "type": "string",
                    "format": "ssh_private_key",
                    "secret": True,
                    "multiline": True,
                },
                {
                    "id": "ssh_key_unlock",
                    "label": "Private Key Passphrase",
                    "type": "string",
                    "secret": True,
                },
            ]
        },
        "injectors": {},
        "managed": True,
    },
    {
        "name": enums.DefaultCredentialType.REGISTRY,
        "kind": "registry",
        "namespace": "registry",
        "inputs": {
            "fields": [
                {
                    "id": "host",
                    "label": "Authentication URL",
                    "type": "string",
                    "help_text": (
                        "Authentication endpoint for the container registry."
                    ),
                    "default": "quay.io",
                },
                {"id": "username", "label": "Username", "type": "string"},
                {
                    "id": "password",
                    "label": "Password or Token",
                    "type": "string",
                    "secret": True,
                    "help_text": (
                        "A password or token used to authenticate with"
                    ),
                },
                {
                    "id": "verify_ssl",
                    "label": "Verify SSL",
                    "type": "boolean",
                    "default": True,
                },
            ],
            "required": ["host"],
        },
        "injectors": {},
        "managed": True,
    },
    {
        "name": enums.DefaultCredentialType.GPG,
        "kind": "cryptography",
        "namespace": "gpg_public_key",
        "inputs": {
            "fields": [
                {
                    "id": "gpg_public_key",
                    "label": "GPG Public Key",
                    "type": "string",
                    "secret": True,
                    "multiline": True,
                    "help_text": (
                        "GPG Public Key used to validate content signatures."
                    ),
                },
            ],
            "required": ["gpg_public_key"],
        },
        "injectors": {},
        "managed": True,
    },
    {
        "name": enums.DefaultCredentialType.AAP,
        "kind": "cloud",
        "namespace": "controller",
        "inputs": {
            "fields": [
                {
                    "id": "host",
                    "label": "Red Hat Ansible Automation Platform",
                    "type": "string",
                    "help_text": (
                        "Red Hat Ansible Automation Platform base URL"
                        " to authenticate with."
                    ),
                },
                {
                    "id": "username",
                    "label": "Username",
                    "type": "string",
                    "help_text": (
                        "Red Hat Ansible Automation Platform username id"
                        " to authenticate as.This should not be set if"
                        " an OAuth token is being used."
                    ),
                },
                {
                    "id": "password",
                    "label": "Password",
                    "type": "string",
                    "secret": True,
                },
                {
                    "id": "oauth_token",
                    "label": "OAuth Token",
                    "type": "string",
                    "secret": True,
                    "help_text": (
                        "An OAuth token to use to authenticate with."
                        "This should not be set if username/password"
                        " are being used."
                    ),
                },
                {
                    "id": "verify_ssl",
                    "label": "Verify SSL",
                    "type": "boolean",
                    "secret": False,
                },
            ],
            "required": ["host"],
        },
        "injectors": {
            "env": {
                "TOWER_HOST": "{{host}}",
                "TOWER_USERNAME": "{{username}}",
                "TOWER_PASSWORD": "{{password}}",
                "TOWER_VERIFY_SSL": "{{verify_ssl}}",
                "TOWER_OAUTH_TOKEN": "{{oauth_token}}",
                "CONTROLLER_HOST": "{{host}}",
                "CONTROLLER_USERNAME": "{{username}}",
                "CONTROLLER_PASSWORD": "{{password}}",
                "CONTROLLER_VERIFY_SSL": "{{verify_ssl}}",
                "CONTROLLER_OAUTH_TOKEN": "{{oauth_token}}",
            }
        },
        "managed": True,
    },
    {
        "name": enums.DefaultCredentialType.VAULT,
        "namespace": "vault",
        "kind": "vault",
        "inputs": {
            "fields": [
                {
                    "id": "vault_password",
                    "label": "Vault Password",
                    "type": "string",
                    "secret": True,
                    "ask_at_runtime": True,
                },
                {
                    "id": "vault_id",
                    "label": "Vault Identifier",
                    "type": "string",
                    "format": "vault_id",
                    "help_text": (
                        "Specify an (optional) Vault ID. This is equivalent "
                        "to specifying the --vault-id Ansible parameter for "
                        "providing multiple Vault passwords.  Note: this "
                        " feature only works in Ansible 2.4+."
                    ),
                },
            ],
            "required": ["vault_password"],
        },
        "injectors": {},
        "managed": True,
    },
]
