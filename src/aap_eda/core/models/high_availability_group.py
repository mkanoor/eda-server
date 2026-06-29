#  Copyright 2022 Red Hat, Inc.
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

import uuid

from django.db import models

from .base import BaseOrgModel, PrimordialModel, UniqueNamedModel

__all__ = ("HighAvailabilityGroup",)


class HighAvailabilityGroup(
    BaseOrgModel,
    UniqueNamedModel,
    PrimordialModel,
):
    """
    Model representing a high-availability activation group.

    A HighAvailabilityGroup groups multiple Activations running on different
    nodes across the world to support HA (High Availability). All activations
    in the group must share the same configuration (rulebook, decision
    environment, credentials, etc.).
    """

    class Meta:
        db_table = "core_high_availability_group"
        indexes = [
            models.Index(fields=["name"], name="ix_ha_group_name"),
            models.Index(fields=["uuid"], name="ix_ha_group_uuid"),
        ]
        ordering = ("-created_at",)
        default_permissions = ["add", "view", "change", "delete"]

    description = models.TextField(
        default="",
        blank=True,
    )
    uuid = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True,
        help_text="UUID used for HA coordination across activation instances",
    )
    service_stats = models.JSONField(
        default=dict,
        blank=True,
        help_text=(
            "Statistics about the group including current leader, "
            "member health, etc."
        ),
    )
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    modified_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return self.name

    @property
    def activation_count(self):
        """Return the number of activations in this group."""
        return self.activations.count()

    def get_first_activation(self):
        """Get the first activation for parameter validation.

        Returns the first activation in the group to use as reference
        for parameter validation.
        """
        return self.activations.order_by("created_at").first()
