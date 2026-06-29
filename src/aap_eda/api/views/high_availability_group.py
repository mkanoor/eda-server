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
"""HighAvailabilityGroup API ViewSet."""
import logging

from ansible_base.rbac.api.related import check_related_permissions
from ansible_base.rbac.models import RoleDefinition
from django.db import transaction
from django.forms import model_to_dict
from django_filters import rest_framework as defaultfilters
from drf_spectacular.utils import (
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from rest_framework import status, viewsets
from rest_framework.decorators import action
from rest_framework.response import Response

from aap_eda.api import exceptions as api_exc, serializers
from aap_eda.core import models
from aap_eda.core.utils import logging_utils

logger = logging.getLogger(__name__)

resource_name = "HighAvailabilityGroup"


@extend_schema_view(
    list=extend_schema(
        description="List all high availability groups",
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                serializers.HighAvailabilityGroupReadSerializer(many=True),
                description="Return a list of high availability groups.",
            ),
        },
    ),
    retrieve=extend_schema(
        description="Get a high availability group by ID",
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                serializers.HighAvailabilityGroupReadSerializer,
                description="Return the high availability group details.",
            ),
        },
    ),
    create=extend_schema(
        description="Create a new high availability group",
        request=serializers.HighAvailabilityGroupSerializer,
        responses={
            status.HTTP_201_CREATED: OpenApiResponse(
                serializers.HighAvailabilityGroupReadSerializer,
                description=(
                    "Return the newly created high availability group."
                ),
            ),
        },
    ),
    partial_update=extend_schema(
        description="Partially update a high availability group",
        request=serializers.HighAvailabilityGroupSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                serializers.HighAvailabilityGroupReadSerializer,
                description="Return the updated high availability group.",
            ),
        },
    ),
    destroy=extend_schema(
        description="Delete a high availability group",
        responses={
            status.HTTP_204_NO_CONTENT: OpenApiResponse(
                None, description="Deletion successful."
            ),
            status.HTTP_409_CONFLICT: OpenApiResponse(
                description=(
                    "Group has active activations and cannot be deleted."
                )
            ),
        },
    ),
)
class HighAvailabilityGroupViewSet(viewsets.ModelViewSet):
    """ViewSet for managing HighAvailabilityGroup resources."""

    queryset = models.HighAvailabilityGroup.objects.order_by("-created_at")
    filter_backends = (defaultfilters.DjangoFilterBackend,)
    rbac_action = None

    def get_serializer_class(self):
        if self.action in ["list", "retrieve"]:
            return serializers.HighAvailabilityGroupReadSerializer
        return serializers.HighAvailabilityGroupSerializer

    def get_response_serializer_class(self):
        return serializers.HighAvailabilityGroupReadSerializer

    def filter_queryset(self, queryset):
        return super().filter_queryset(
            queryset.model.access_qs(self.request.user, queryset=queryset)
        )

    def get_serializer_context(self):
        context = super().get_serializer_context()
        # Include full activation list for detail view
        if self.action == "retrieve":
            context["include_activations"] = True
        return context

    def retrieve(self, request, *args, **kwargs):
        """Retrieve a single high availability group."""
        high_availability_group = self.get_object()

        logger.info(
            logging_utils.generate_simple_audit_log(
                "Read",
                resource_name,
                high_availability_group.name,
                high_availability_group.id,
                high_availability_group.organization,
            )
        )

        serializer = self.get_serializer(high_availability_group)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        """Create a new high availability group."""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        with transaction.atomic():
            high_availability_group = serializer.save()

            # Check RBAC permissions for creating this resource
            check_related_permissions(
                request.user,
                serializer.Meta.model,
                {},
                model_to_dict(serializer.instance),
            )

            # Give creator permissions to the user who created this resource
            RoleDefinition.objects.give_creator_permissions(
                request.user, serializer.instance
            )

        logger.info(
            logging_utils.generate_simple_audit_log(
                "Create",
                resource_name,
                high_availability_group.name,
                high_availability_group.id,
                high_availability_group.organization,
            )
        )

        # Refresh from DB to ensure all related fields are loaded
        high_availability_group.refresh_from_db()

        read_serializer = self.get_response_serializer_class()(
            high_availability_group, context=self.get_serializer_context()
        )
        return Response(read_serializer.data, status=status.HTTP_201_CREATED)

    def partial_update(self, request, *args, **kwargs):
        """Update a high availability group partially."""
        high_availability_group = self.get_object()
        serializer = self.get_serializer(
            high_availability_group, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        logger.info(
            logging_utils.generate_simple_audit_log(
                "Update",
                resource_name,
                high_availability_group.name,
                high_availability_group.id,
                high_availability_group.organization,
            )
        )

        read_serializer = self.get_response_serializer_class()(
            high_availability_group
        )
        return Response(read_serializer.data)

    def destroy(self, request, *args, **kwargs):
        """Delete a high availability group."""
        high_availability_group = self.get_object()

        # Check if there are any activations in this group
        activation_count = high_availability_group.activation_count
        if activation_count > 0:
            raise api_exc.Conflict(
                f"High availability group "
                f"'{high_availability_group.name}' has "
                f"{activation_count} activation(s) and cannot be deleted. "
                f"Please remove all activations from the group first."
            )

        logger.info(
            logging_utils.generate_simple_audit_log(
                "Delete",
                resource_name,
                high_availability_group.name,
                high_availability_group.id,
                high_availability_group.organization,
            )
        )

        self.perform_destroy(high_availability_group)
        return Response(status=status.HTTP_204_NO_CONTENT)

    @extend_schema(
        description="Get all activations in this group",
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                serializers.HighAvailabilityGroupReadSerializer,
                description="Return list of activations in the group.",
            ),
        },
    )
    @action(detail=True, methods=["get"], url_path="activations")
    def activations(self, request, pk=None):
        """Get all activations in this group."""
        high_availability_group = self.get_object()
        activations = high_availability_group.activations.all()

        from aap_eda.api.serializers.high_availability_group import (
            ActivationRefSerializer,
        )

        serializer = ActivationRefSerializer(activations, many=True)
        return Response(serializer.data)
