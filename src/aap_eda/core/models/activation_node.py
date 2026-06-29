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

import uuid

from django.db import models

__all__ = ("ActivationNode",)


class ActivationNode(models.Model):
    """Represents a worker node for podman activations.

    ActivationNodes are automatically created from RULEBOOK_WORKER_QUEUES
    setting at startup. Each node represents a queue that workers can
    process activations from. Users can customize the name and description
    but cannot change the queue_name or uuid.
    """

    class Meta:
        db_table = "core_activation_node"
        default_permissions = ("add", "view", "change", "delete")
        indexes = [
            models.Index(fields=["queue_name"], name="ix_node_queue_name")
        ]
        ordering = ("queue_name",)

    uuid = models.UUIDField(
        default=uuid.uuid4,
        editable=False,
        unique=True,
        help_text="Unique identifier for this node",
    )
    queue_name = models.TextField(
        unique=True,
        help_text=(
            "Queue name from RULEBOOK_WORKER_QUEUES "
            "(read-only, set at creation)"
        ),
    )
    name = models.TextField(
        unique=True,
        help_text="User-friendly name for this node",
    )
    description = models.TextField(
        default="",
        blank=True,
        help_text="Optional description of this node",
    )
    created_at = models.DateTimeField(auto_now_add=True, null=False)
    modified_at = models.DateTimeField(auto_now=True, null=False)

    def __str__(self):
        return f"{self.name} ({self.queue_name})"
