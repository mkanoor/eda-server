#  Copyright 2023 Red Hat, Inc.
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
import hashlib
import logging

import yaml
from rest_framework import serializers

from aap_eda.core import models

logger = logging.getLogger(__name__)

EDA_VALID_HASH_FORMATS = ("hex", "base64")

EDA_VALID_WEBHOOK_AUTH_TYPES = ("hmac", "token")


def check_if_rulebook_exists(rulebook_id: int) -> int:
    try:
        models.Rulebook.objects.get(pk=rulebook_id)
    except models.Rulebook.DoesNotExist:
        raise serializers.ValidationError(
            f"Rulebook with id {rulebook_id} does not exist"
        )
    return rulebook_id


def check_if_de_exists(decision_environment_id: int) -> int:
    try:
        de = models.DecisionEnvironment.objects.get(pk=decision_environment_id)
        if de.credential_id:
            models.Credential.objects.get(pk=de.credential_id)
    except models.Credential.DoesNotExist:
        raise serializers.ValidationError(
            f"Credential with id {de.credential_id} does not exist"
        )
    except models.DecisionEnvironment.DoesNotExist:
        raise serializers.ValidationError(
            f"DecisionEnvironment with id {decision_environment_id} "
            "does not exist"
        )
    return decision_environment_id


def check_if_extra_var_exists(extra_var_id: int) -> int:
    try:
        models.ExtraVar.objects.get(pk=extra_var_id)
    except models.ExtraVar.DoesNotExist:
        raise serializers.ValidationError(
            f"ExtraVar with id {extra_var_id} does not exist"
        )
    return extra_var_id


def check_awx_tokens(user_id: int) -> int:
    tokens = models.AwxToken.objects.filter(user_id=user_id).count()
    if tokens == 0:
        raise serializers.ValidationError("No controller token specified")
    elif tokens > 1:
        raise serializers.ValidationError(
            "More than one controller token found, "
            "currently only 1 token is supported"
        )

    return user_id


def is_extra_var_dict(extra_var: str):
    try:
        data = yaml.safe_load(extra_var)
        if not isinstance(data, dict):
            raise serializers.ValidationError(
                "Extra var is not in object format"
            )
    except yaml.YAMLError:
        raise serializers.ValidationError(
            "Extra var must be in JSON or YAML format"
        )


def valid_hash_algorithm(algo: str):
    if algo not in hashlib.algorithms_available:
        raise serializers.ValidationError(
            (
                f"Invalid hash algorithm {algo} should "
                f"be one of {hashlib.algorithms_available}"
            )
        )


def valid_hash_format(fmt: str):
    if fmt not in EDA_VALID_HASH_FORMATS:
        raise serializers.ValidationError(
            (
                f"Invalid hash format {fmt} should "
                f"be one of {EDA_VALID_HASH_FORMATS}"
            )
        )
    return fmt


def valid_webhook_auth_type(auth_type: str):
    if auth_type not in EDA_VALID_WEBHOOK_AUTH_TYPES:
        raise serializers.ValidationError(
            (
                f"Invalid auth_type{auth_type} should "
                f"be one of {EDA_VALID_WEBHOOK_AUTH_TYPES}"
            )
        )
    return auth_type


def check_if_webhooks_exists(webhook_ids: list[int]) -> list[int]:
    for webhook_id in webhook_ids:
        try:
            models.Webhook.objects.get(pk=webhook_id)
        except models.Webhook.DoesNotExist:
            raise serializers.ValidationError(
                f"Webhook with id {webhook_id} does not exist"
            )
    return webhook_ids
