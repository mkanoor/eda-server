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
"""ActivationNode API ViewSet."""
import logging

from django_filters import rest_framework as defaultfilters
from drf_spectacular.utils import (
    OpenApiResponse,
    extend_schema,
    extend_schema_view,
)
from rest_framework import status, viewsets
from rest_framework.response import Response

from aap_eda.api import serializers
from aap_eda.core import models

logger = logging.getLogger(__name__)


@extend_schema_view(
    list=extend_schema(
        description="List all activation nodes",
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                serializers.ActivationNodeSerializer(many=True),
                description="Return a list of activation nodes.",
            ),
        },
    ),
    retrieve=extend_schema(
        description="Get details of an activation node",
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                serializers.ActivationNodeSerializer,
                description="Return details of the activation node.",
            ),
        },
    ),
    partial_update=extend_schema(
        description="Partially update an activation node",
        request=serializers.ActivationNodeSerializer,
        responses={
            status.HTTP_200_OK: OpenApiResponse(
                serializers.ActivationNodeSerializer,
                description="Return the updated activation node.",
            ),
        },
    ),
)
class ActivationNodeViewSet(viewsets.ModelViewSet):
    """ViewSet for managing activation nodes.

    Activation nodes are automatically created from RULEBOOK_WORKER_QUEUES.
    Users can only update the name and description fields.
    Creation and deletion are not allowed via API.
    """

    queryset = models.ActivationNode.objects.all()
    serializer_class = serializers.ActivationNodeSerializer
    filter_backends = [defaultfilters.DjangoFilterBackend]
    filterset_fields = ["queue_name", "name"]
    rbac_action = None

    http_method_names = ["get", "patch", "head", "options"]

    def partial_update(self, request, *args, **kwargs):
        """Update activation node name and description only."""
        activation_node = self.get_object()
        serializer = self.get_serializer(
            activation_node, data=request.data, partial=True
        )
        serializer.is_valid(raise_exception=True)
        serializer.save()

        return Response(serializer.data, status=status.HTTP_200_OK)
