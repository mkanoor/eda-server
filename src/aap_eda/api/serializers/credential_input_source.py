#  Copyright 2025 Red Hat, Inc.
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
from django.db.models import Q
from django.urls import reverse
from drf_spectacular.utils import extend_schema_field
from rest_framework import serializers

from aap_eda.api.serializers.credential_type import CredentialTypeRefSerializer
from aap_eda.api.serializers.eda_credential import EdaCredentialReferenceField
from aap_eda.api.serializers.fields.basic_user import BasicUserFieldSerializer
from aap_eda.api.serializers.organization import OrganizationRefSerializer
from aap_eda.api.serializers.user import BasicUserSerializer
from aap_eda.core import enums, models, validators
from aap_eda.core.utils.credentials import (
    inputs_to_display,
    validate_inputs,
)
from aap_eda.core.utils.crypto.base import SecretValue


class CredentialInputSourceReferenceSerializer(serializers.Serializer):
    type = serializers.CharField(
        required=True, help_text="Type of the related resource"
    )
    id = serializers.IntegerField(
        required=True, help_text="ID of the related resource"
    )
    name = serializers.CharField(
        required=True, help_text="Name of the related resource"
    )
    uri = serializers.URLField(
        required=True, help_text="URI of the related resource"
    )


@extend_schema_field(CredentialInputSourceReferenceSerializer(many=True))
class CredentialInputSourceReferenceField(serializers.JSONField):
    pass


class CredentialInputSourceSerializer(serializers.ModelSerializer):
    organization = OrganizationRefSerializer()
    references = EdaCredentialReferenceField(required=False, allow_null=True)
    created_by = BasicUserFieldSerializer()
    modified_by = BasicUserFieldSerializer()

    class Meta:
        model = models.CredentialInputSource
        read_only_fields = [
            "id",
            "created_at",
            "modified_at",
            "organization",
        ]
        fields = [
            "description",
            "metadata",
            "references",
            "created_by",
            "modified_by",
            "input_field_name",
            "source_credential",
            "target_credential",
            *read_only_fields,
        ]

    def to_representation(self, obj):
        organization = (
            OrganizationRefSerializer(obj.organization).data
            if obj.organization
            else None
        )

        if not hasattr(self, "references"):
            self.references = None

        return {
            "id": obj.id,
            "source_credential": obj.source_credential.id,
            "target_credential": obj.target_credential.id,
            "input_field_name": obj.input_field_name,
            "metadata": _get_metadata(obj),
            "organization": organization,
            "references": self.references,
            "created_at": obj.created_at,
            "modified_at": obj.modified_at,
            "created_by": BasicUserSerializer(obj.created_by).data,
            "modified_by": BasicUserSerializer(obj.modified_by).data,
        }


class CredentialInputSourceCreateSerializer(serializers.ModelSerializer):
    target_credential = serializers.IntegerField(
        required=True,
        allow_null=False,
        validators=[validators.check_if_eda_credential_exists],
        error_messages={
            "null": "Target Credential is needed",
            "required": "Target Credential is required",
        },
    )
    source_credential = serializers.IntegerField(
        required=True,
        allow_null=False,
        validators=[validators.check_if_eda_credential_exists],
        error_messages={
            "null": "Source Credential is needed",
            "required": "Source Credential is required",
        },
    )
    organization_id = serializers.IntegerField(
        required=True,
        allow_null=False,
        validators=[validators.check_if_organization_exists],
        error_messages={
            "null": "Organization is needed",
            "required": "Organization is required",
        },
    )
    metadata = serializers.JSONField()

    def validate(self, data):
        source_credential = models.EdaCredential.objects.get(
            id=data.get("source_credential")
        )
        target_credential = models.EdaCredential.objects.get(
            id=data.get("target_credential")
        )

        metadata = data.get("metadata", {})
        errors = validate_inputs(
            source_credential.credential_type,
            source_credential.credential_type.inputs,
            metadata,
            "metadata",
        )
        if bool(errors):
            raise serializers.ValidationError(errors)

        validators.check_if_field_exists(
            target_credential.credential_type.inputs,
            data.get("input_field_name"),
        )

        data["source_credential"] = source_credential
        data["target_credential"] = target_credential

        return data

    class Meta:
        model = models.CredentialInputSource
        fields = [
            "description",
            "metadata",
            "target_credential",
            "source_credential",
            "input_field_name",
            "organization_id",
        ]


class CredentialInputSourceUpdateSerializer(serializers.ModelSerializer):
    organization_id = serializers.IntegerField(
        required=True,
        allow_null=False,
        validators=[validators.check_if_organization_exists],
        error_messages={"null": "Organization is needed"},
    )
    metadata = serializers.JSONField()

    def validate(self, data):
        credential_type = self.instance.source_credential.credential_type

        metadata = data.get("metadata", {})
        # allow empty metadata during updating
        if self.partial and not bool(metadata):
            return data

        errors = validate_inputs(
            credential_type, credential_type.inputs, metadata, "metadata"
        )
        if bool(errors):
            raise serializers.ValidationError(errors)

        return data

    class Meta:
        model = models.CredentialInputSource
        fields = [
            "description",
            "metadata",
            "organization_id",
            "source_credential",
            "target_credential",
            "input_field_name",
        ]


class CredentialInputSourceRefSerializer(serializers.ModelSerializer):
    """Serializer for CredentialInputSource reference."""

    metadata = serializers.SerializerMethodField()

    class Meta:
        model = models.CredentialInputSource
        fields = [
            "id",
            "description",
            "metadata",
            "organization_id",
            "source_credential",
            "target_credential",
        ]
        read_only_fields = ["id"]

    def get_metadata(self, obj) -> dict:
        return _get_metadata(obj)


def _get_metadata(obj) -> dict:
    metadata = (
        obj.metadata.get_secret_value()
        if isinstance(obj.metadata, SecretValue)
        else obj.metadata
    )
    return inputs_to_display(
        obj.source_credential.credential_type.inputs, metadata, "metadata"
    )
