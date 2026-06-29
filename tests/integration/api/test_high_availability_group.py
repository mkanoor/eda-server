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
def test_create_high_availability_group(
    default_organization: models.Organization,
    admin_client: APIClient,
):
    """Test creating a HighAvailabilityGroup via REST API."""
    payload = {
        "name": "test-ha-group",
        "description": "Test HA group for activations",
        "organization_id": default_organization.id,
    }

    response = admin_client.post(
        f"{api_url_v1}/high-availability-groups/", data=payload
    )
    assert response.status_code == status.HTTP_201_CREATED

    data = response.data
    assert data["name"] == "test-ha-group"
    assert data["description"] == "Test HA group for activations"
    assert data["organization"]["id"] == default_organization.id
    assert "uuid" in data
    assert "id" in data
    assert "created_at" in data
    assert "modified_at" in data

    # Verify the object was created in the database
    ha_group = models.HighAvailabilityGroup.objects.get(id=data["id"])
    assert ha_group.name == "test-ha-group"
    assert ha_group.description == "Test HA group for activations"
    assert ha_group.organization_id == default_organization.id
    assert ha_group.uuid is not None


@pytest.mark.django_db
def test_list_high_availability_groups(
    default_organization: models.Organization,
    admin_client: APIClient,
):
    """Test listing HighAvailabilityGroups via REST API."""
    # Create a couple of HA groups
    models.HighAvailabilityGroup.objects.create(
        name="ha-group-1",
        description="First HA group",
        organization=default_organization,
    )
    models.HighAvailabilityGroup.objects.create(
        name="ha-group-2",
        description="Second HA group",
        organization=default_organization,
    )

    response = admin_client.get(f"{api_url_v1}/high-availability-groups/")
    assert response.status_code == status.HTTP_200_OK

    data = response.data
    assert data["count"] == 2
    assert len(data["results"]) == 2

    names = {result["name"] for result in data["results"]}
    assert names == {"ha-group-1", "ha-group-2"}


@pytest.mark.django_db
def test_retrieve_high_availability_group(
    default_organization: models.Organization,
    admin_client: APIClient,
):
    """Test retrieving a single HighAvailabilityGroup via REST API."""
    ha_group = models.HighAvailabilityGroup.objects.create(
        name="ha-group-detail",
        description="HA group for detail test",
        organization=default_organization,
    )

    response = admin_client.get(
        f"{api_url_v1}/high-availability-groups/{ha_group.id}/"
    )
    assert response.status_code == status.HTTP_200_OK

    data = response.data
    assert data["id"] == ha_group.id
    assert data["name"] == "ha-group-detail"
    assert data["description"] == "HA group for detail test"
    assert data["organization"]["id"] == default_organization.id
    assert data["uuid"] == str(ha_group.uuid)


@pytest.mark.django_db
def test_update_high_availability_group(
    default_organization: models.Organization,
    admin_client: APIClient,
):
    """Test updating a HighAvailabilityGroup via REST API."""
    ha_group = models.HighAvailabilityGroup.objects.create(
        name="ha-group-update",
        description="Original description",
        organization=default_organization,
    )

    payload = {
        "name": "ha-group-updated",
        "description": "Updated description",
    }

    response = admin_client.patch(
        f"{api_url_v1}/high-availability-groups/{ha_group.id}/",
        data=payload,
    )
    assert response.status_code == status.HTTP_200_OK

    data = response.data
    assert data["name"] == "ha-group-updated"
    assert data["description"] == "Updated description"

    # Verify the object was updated in the database
    ha_group.refresh_from_db()
    assert ha_group.name == "ha-group-updated"
    assert ha_group.description == "Updated description"


@pytest.mark.django_db
def test_delete_high_availability_group(
    default_organization: models.Organization,
    admin_client: APIClient,
):
    """Test deleting a HighAvailabilityGroup via REST API."""
    ha_group = models.HighAvailabilityGroup.objects.create(
        name="ha-group-delete",
        description="HA group to delete",
        organization=default_organization,
    )

    ha_group_id = ha_group.id

    response = admin_client.delete(
        f"{api_url_v1}/high-availability-groups/{ha_group_id}/"
    )
    assert response.status_code == status.HTTP_204_NO_CONTENT

    # Verify the object was deleted from the database
    assert not models.HighAvailabilityGroup.objects.filter(
        id=ha_group_id
    ).exists()


@pytest.mark.django_db
def test_create_high_availability_group_unique_name(
    default_organization: models.Organization,
    admin_client: APIClient,
):
    """Test that HighAvailabilityGroup names must be unique."""
    # Create first HA group
    models.HighAvailabilityGroup.objects.create(
        name="unique-name",
        description="First HA group",
        organization=default_organization,
    )

    # Try to create another with the same name
    payload = {
        "name": "unique-name",
        "description": "Second HA group",
        "organization_id": default_organization.id,
    }

    response = admin_client.post(
        f"{api_url_v1}/high-availability-groups/", data=payload
    )
    assert response.status_code == status.HTTP_400_BAD_REQUEST
