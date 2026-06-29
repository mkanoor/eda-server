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

import pytest
from rest_framework import status
from rest_framework.test import APIClient

from aap_eda.core import models
from tests.integration.constants import api_url_v1


@pytest.mark.django_db
def test_list_activation_nodes(
    admin_client: APIClient,
):
    """Test listing ActivationNodes via REST API."""
    # Create a couple of activation nodes
    models.ActivationNode.objects.create(
        name="Node 1",
        queue_name="activation-node-1",
        description="First activation node",
    )
    models.ActivationNode.objects.create(
        name="Node 2",
        queue_name="activation-node-2",
        description="Second activation node",
    )

    response = admin_client.get(f"{api_url_v1}/activation-nodes/")
    assert response.status_code == status.HTTP_200_OK

    data = response.data
    assert data["count"] >= 2
    assert len(data["results"]) >= 2

    names = {result["name"] for result in data["results"]}
    assert "Node 1" in names
    assert "Node 2" in names


@pytest.mark.django_db
def test_retrieve_activation_node(
    admin_client: APIClient,
):
    """Test retrieving a single ActivationNode via REST API."""
    node = models.ActivationNode.objects.create(
        name="Node Detail",
        queue_name="activation-node-detail",
        description="Node for detail test",
    )

    response = admin_client.get(f"{api_url_v1}/activation-nodes/{node.id}/")
    assert response.status_code == status.HTTP_200_OK

    data = response.data
    assert data["id"] == node.id
    assert data["name"] == "Node Detail"
    assert data["queue_name"] == "activation-node-detail"
    assert data["description"] == "Node for detail test"
    assert data["uuid"] == str(node.uuid)
    assert "created_at" in data
    assert "modified_at" in data


@pytest.mark.django_db
def test_update_activation_node(
    admin_user,
    admin_client: APIClient,
):
    """Test updating an ActivationNode via REST API.

    Only name and description should be updateable.
    queue_name and uuid should be read-only.
    """
    # Give admin user permission to change activation nodes
    admin_user.is_superuser = True
    admin_user.save()
    node = models.ActivationNode.objects.create(
        name="Node Update",
        queue_name="activation-node-update",
        description="Original description",
    )

    original_queue_name = node.queue_name
    original_uuid = node.uuid

    payload = {
        "name": "Node Updated",
        "description": "Updated description",
        # Try to update queue_name (should be ignored)
        "queue_name": "should-not-change",
    }

    response = admin_client.patch(
        f"{api_url_v1}/activation-nodes/{node.id}/",
        data=payload,
    )
    assert response.status_code == status.HTTP_200_OK

    data = response.data
    assert data["name"] == "Node Updated"
    assert data["description"] == "Updated description"
    # queue_name should remain unchanged
    assert data["queue_name"] == original_queue_name

    # Verify the object was updated in the database
    node.refresh_from_db()
    assert node.name == "Node Updated"
    assert node.description == "Updated description"
    assert node.queue_name == original_queue_name
    assert node.uuid == original_uuid


@pytest.mark.django_db
def test_update_activation_node_name_only(
    admin_user,
    admin_client: APIClient,
):
    """Test updating only the name of an ActivationNode."""
    # Give admin user permission to change activation nodes
    admin_user.is_superuser = True
    admin_user.save()
    node = models.ActivationNode.objects.create(
        name="Original Name",
        queue_name="activation-node-name-test",
        description="Test description",
    )

    payload = {
        "name": "New Name",
    }

    response = admin_client.patch(
        f"{api_url_v1}/activation-nodes/{node.id}/",
        data=payload,
    )
    assert response.status_code == status.HTTP_200_OK

    data = response.data
    assert data["name"] == "New Name"
    assert data["description"] == "Test description"  # unchanged

    node.refresh_from_db()
    assert node.name == "New Name"
    assert node.description == "Test description"


@pytest.mark.django_db
def test_update_activation_node_description_only(
    admin_user,
    admin_client: APIClient,
):
    """Test updating only the description of an ActivationNode."""
    # Give admin user permission to change activation nodes
    admin_user.is_superuser = True
    admin_user.save()
    node = models.ActivationNode.objects.create(
        name="Test Node",
        queue_name="activation-node-desc-test",
        description="Original description",
    )

    payload = {
        "description": "New description",
    }

    response = admin_client.patch(
        f"{api_url_v1}/activation-nodes/{node.id}/",
        data=payload,
    )
    assert response.status_code == status.HTTP_200_OK

    data = response.data
    assert data["name"] == "Test Node"  # unchanged
    assert data["description"] == "New description"

    node.refresh_from_db()
    assert node.name == "Test Node"
    assert node.description == "New description"


@pytest.mark.django_db
def test_cannot_create_activation_node_via_api(
    admin_client: APIClient,
):
    """Test that ActivationNodes cannot be created via the API.

    ActivationNodes are created automatically from RULEBOOK_WORKER_QUEUES
    at startup, so the API should not allow creation.
    """
    payload = {
        "name": "New Node",
        "queue_name": "new-queue",
        "description": "Should not be created",
    }

    response = admin_client.post(
        f"{api_url_v1}/activation-nodes/", data=payload
    )
    # Should return 405 Method Not Allowed or 403 Forbidden
    assert response.status_code in [
        status.HTTP_403_FORBIDDEN,
        status.HTTP_405_METHOD_NOT_ALLOWED,
    ]


@pytest.mark.django_db
def test_cannot_delete_activation_node_via_api(
    admin_client: APIClient,
):
    """Test that ActivationNodes cannot be deleted via the API.

    ActivationNodes are system-managed and should not be deletable.
    """
    node = models.ActivationNode.objects.create(
        name="Test Node",
        queue_name="activation-node-delete-test",
        description="Test node",
    )

    response = admin_client.delete(f"{api_url_v1}/activation-nodes/{node.id}/")
    # Should return 405 Method Not Allowed or 403 Forbidden
    assert response.status_code in [
        status.HTTP_403_FORBIDDEN,
        status.HTTP_405_METHOD_NOT_ALLOWED,
    ]

    # Verify the node still exists
    assert models.ActivationNode.objects.filter(id=node.id).exists()


@pytest.mark.django_db
def test_activation_node_unique_queue_name(
    admin_client: APIClient,
):
    """Test that ActivationNode queue_names must be unique."""
    # Create first node
    models.ActivationNode.objects.create(
        name="Node 1",
        queue_name="unique-queue",
        description="First node",
    )

    # Try to create another with the same queue_name
    # This should fail at the database level due to unique constraint
    with pytest.raises(Exception):  # Will raise IntegrityError
        models.ActivationNode.objects.create(
            name="Node 2",
            queue_name="unique-queue",
            description="Second node",
        )


@pytest.mark.django_db
def test_activation_node_unique_name(
    admin_client: APIClient,
):
    """Test that ActivationNode names must be unique."""
    # Create first node
    models.ActivationNode.objects.create(
        name="Unique Name",
        queue_name="queue-1",
        description="First node",
    )

    # Try to create another with the same name
    # This should fail at the database level due to unique constraint
    with pytest.raises(Exception):  # Will raise IntegrityError
        models.ActivationNode.objects.create(
            name="Unique Name",
            queue_name="queue-2",
            description="Second node",
        )
