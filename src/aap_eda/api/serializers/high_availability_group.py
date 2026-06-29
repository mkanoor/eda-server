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

from rest_framework import serializers

from aap_eda.api.serializers.fields.basic_user import BasicUserFieldSerializer
from aap_eda.api.serializers.mixins import OrganizationIdFieldMixin
from aap_eda.api.serializers.organization import OrganizationRefSerializer
from aap_eda.api.serializers.user import BasicUserSerializer
from aap_eda.core import models


class HighAvailabilityGroupSerializer(
    OrganizationIdFieldMixin, serializers.ModelSerializer
):
    """Serializer for creating and updating HighAvailabilityGroup."""

    organization_id = serializers.IntegerField(
        required=True,
        allow_null=False,
        error_messages={"null": "Organization is needed"},
    )

    class Meta:
        model = models.HighAvailabilityGroup
        fields = [
            "name",
            "description",
            "organization_id",
            "service_stats",
        ]


class HighAvailabilityGroupRefSerializer(serializers.ModelSerializer):
    """Reference serializer for HighAvailabilityGroup in nested objects."""

    class Meta:
        model = models.HighAvailabilityGroup
        fields = ["id", "name", "description"]
        read_only_fields = ["id", "name", "description"]


class ActivationRefSerializer(serializers.ModelSerializer):
    """Minimal activation reference for listing activations in a group."""

    class Meta:
        model = models.Activation
        fields = [
            "id",
            "name",
            "description",
            "status",
            "is_enabled",
            "created_at",
        ]
        read_only_fields = fields


class HighAvailabilityGroupReadSerializer(serializers.ModelSerializer):
    """Serializer for reading HighAvailabilityGroup details."""

    organization = OrganizationRefSerializer(required=False)
    created_by = BasicUserFieldSerializer()
    modified_by = BasicUserFieldSerializer()
    activation_count = serializers.IntegerField(read_only=True)
    activations = serializers.SerializerMethodField()

    class Meta:
        model = models.HighAvailabilityGroup
        fields = [
            "id",
            "name",
            "description",
            "uuid",
            "organization",
            "service_stats",
            "activation_count",
            "activations",
            "created_at",
            "modified_at",
            "created_by",
            "modified_by",
        ]
        read_only_fields = [
            "id",
            "uuid",
            "activation_count",
            "created_at",
            "modified_at",
        ]

    def get_activations(self, obj):
        """Return list of activations in this group."""
        # Check if we should include the full list
        # For list view, don't include; for detail view, include
        if self.context.get("include_activations", False):
            activations = obj.activations.all()
            return ActivationRefSerializer(activations, many=True).data
        return None

    def to_representation(self, high_availability_group):
        """Convert HighAvailabilityGroup to dictionary representation."""
        data = super().to_representation(high_availability_group)
        # Manually serialize User objects
        data["created_by"] = (
            BasicUserSerializer(high_availability_group.created_by).data
            if high_availability_group.created_by
            else None
        )
        data["modified_by"] = (
            BasicUserSerializer(high_availability_group.modified_by).data
            if high_availability_group.modified_by
            else None
        )
        return data
