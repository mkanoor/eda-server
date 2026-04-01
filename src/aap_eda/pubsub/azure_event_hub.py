#  Copyright 2026 Red Hat, Inc.
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
import json
import logging
import uuid
from typing import Any, Optional

from azure.eventhub import EventData, EventHubProducerClient
from azure.identity import ClientSecretCredential
from azure.mgmt.eventhub import EventHubManagementClient
from azure.mgmt.eventhub.models import ConsumerGroup, Eventhub

from .exceptions import ProducerException
from .interfaces import MessageProducer, hash_activation_name

LOGGER = logging.getLogger(__name__)


class AzureEventHubProducer(MessageProducer):
    """Azure Event Hub message producer implementation.

    Provides publishing capabilities to Azure Event Hubs and generates
    consumer manifests for remote activation nodes.
    """

    REVERSE_MAP_EXTRA_VARS = {
        "azure_tenant_id": "{{ event_hub_pubsub_tenant_id }}",
        "azure_client_id": "{{ event_hub_pubsub_client_id }}",
        "azure_client_secret": "{{ event_hub_pubsub_client_secret }}",
        "azure_namespace": "{{ event_hub_pubsub_namespace }}",
        "azure_event_hub_name": "{{ event_hub_pubsub_event_hub_name }}",
        "azure_consumer_group": "{{ event_hub_pubsub_consumer_group }}",
        "azure_starting_position": "{{ event_hub_pubsub_starting_position }}",
        "azure_storage_account_name": "{{ event_hub_pubsub_storage_account_name }}",
        "azure_checkpoint_container_name": "{{ event_hub_pubsub_checkpoint_container_name }}",
        "azure_max_wait_time": "{{ event_hub_pubsub_max_wait_time }}",
        "feedback_timeout": "{{ event_hub_pubsub_feedback_timeout }}",
    }
    SOURCE_PLUGIN_TYPE = "azure.azcollection.azure_event_hub"

    # Required fields for basic authentication
    REQUIRED_AUTH_FIELDS = [
        "tenant_id",
        "client_id",
        "client_secret",
        "namespace",
    ]
    # Required fields for management operations (topic/consumer group creation)
    REQUIRED_MGMT_FIELDS = ["subscription_id", "resource_group"]

    def __init__(self, args: dict[str, Any], topic: Optional[str] = None):
        """Initialize Azure Event Hub producer.

        Args:
            args: Configuration dictionary containing Azure credentials
                and settings.
            topic: Optional topic/event hub name. If not provided, will
                use 'event_hub_name' from args.

        Raises:
            ValueError: If required authentication fields are missing or topic
                cannot be determined.
        """
        self.inputs = args

        # Validate required authentication fields
        self._validate_required_fields(self.REQUIRED_AUTH_FIELDS)

        # Determine topic
        if args.get("dynamic_topic", False):
            self.topic = topic or self.inputs.get("event_hub_name")
        else:
            self.topic = self.inputs.get("event_hub_name")

        if not self.topic:
            raise ValueError("Topic must be specified")

        # Validate management fields if dynamic features are enabled
        if args.get("dynamic_topic", False) or args.get(
            "dynamic_groups", False
        ):
            self._validate_required_fields(self.REQUIRED_MGMT_FIELDS)

    def _validate_required_fields(self, required_fields: list[str]) -> None:
        """Validate that required fields are present in inputs.

        Args:
            required_fields: List of required field names.

        Raises:
            ValueError: If any required field is missing.
        """
        missing_fields = [
            field for field in required_fields if field not in self.inputs
        ]
        if missing_fields:
            raise ValueError(
                f"Missing required fields for Azure Event Hub: "
                f"{', '.join(missing_fields)}"
            )

    def _create_consumer_group(self, name: str) -> None:
        """Create a consumer group in the Azure Event Hub.

        Args:
            name: The name of the consumer group to create.

        Raises:
            ProducerException: If consumer group creation fails.
        """
        try:
            client = EventHubManagementClient(
                self._get_credential(), self.inputs["subscription_id"]
            )
            # Extract namespace name from FQDN if necessary
            namespace = self.inputs["namespace"].split(".")[0]
            client.consumer_groups.create_or_update(
                self.inputs["resource_group"],
                namespace,
                self.topic,
                name,
                ConsumerGroup(),
            )
            LOGGER.info(
                "Created/updated consumer group '%s' under Event Hub '%s'",
                name,
                self.topic,
            )
        except Exception as e:
            LOGGER.error(
                "Error creating consumer group '%s': %s", name, str(e)
            )
            raise ProducerException(
                f"Error creating consumer group '{name}'"
            ) from e

    def get_consumer_manifest(self, activation_name: str) -> dict[str, Any]:
        """Generate the consumer configuration manifest.

        Creates the configuration required to spawn a consumer for this
        Azure Event Hub on a remote activation node. If dynamic_groups is
        enabled, creates a dedicated consumer group for the activation.

        Args:
            activation_name: The name of the activation (not yet saved to DB).

        Returns:
            A dictionary containing source_type and args for the consumer.

        Raises:
            ProducerException: If dynamic_groups is enabled but the Event Hub
                doesn't exist and dynamic_topic is disabled.
        """
        local_args = self.__class__.REVERSE_MAP_EXTRA_VARS.copy()

        # If dynamic_topic is enabled, create the Event Hub first
        # (required before creating consumer groups)
        if self.inputs.get("dynamic_topic", False):
            self._create_topic()
        elif self.inputs.get("dynamic_groups", False):
            # If dynamic_topic is disabled but dynamic_groups is enabled,
            # the Event Hub must already exist. We'll let the consumer group
            # creation fail with a clear error if the Event Hub doesn't exist.
            LOGGER.warning(
                "dynamic_groups is enabled but dynamic_topic is disabled. "
                "Event Hub '%s' must already exist or consumer group creation will fail.",
                self.topic,
            )

        if self.inputs.get("dynamic_groups", False):
            # Use hashed activation name to avoid exceeding consumer group limits
            hashed_name = hash_activation_name(activation_name)
            name = f"activation-{hashed_name}"
            self._create_consumer_group(name)
            local_args["azure_consumer_group"] = name
        local_args["azure_event_hub_name"] = self.topic
        local_args["feedback"] = self.inputs.get("feedback", False)

        return {
            "source_type": self.__class__.SOURCE_PLUGIN_TYPE,
            "args": local_args,
        }

    def _get_credential(self) -> ClientSecretCredential:
        """Create Azure credentials from inputs.

        Returns:
            ClientSecretCredential configured with tenant, client ID,
            and secret.
        """
        return ClientSecretCredential(
            tenant_id=self.inputs["tenant_id"],
            client_id=self.inputs["client_id"],
            client_secret=self.inputs["client_secret"],
        )

    def _create_topic(self) -> None:
        """Create or update the Event Hub (topic).

        Creates a new Event Hub with default settings (1 day retention,
        2 partitions) or updates an existing one.

        Raises:
            ProducerException: If Event Hub creation fails.
        """
        try:
            client = EventHubManagementClient(
                self._get_credential(), self.inputs["subscription_id"]
            )
            eventhub_params = Eventhub(
                message_retention_in_days=1, partition_count=2
            )
            # Extract namespace name from FQDN if necessary
            namespace = self.inputs["namespace"].split(".")[0]
            client.event_hubs.create_or_update(
                self.inputs["resource_group"],
                namespace,
                self.topic,
                eventhub_params,
            )
            LOGGER.info("Created/updated Event Hub '%s'", self.topic)
        except Exception as e:
            LOGGER.error(
                "Error creating Event Hub '%s': %s", self.topic, str(e)
            )
            raise ProducerException(
                f"Error creating Event Hub '{self.topic}'"
            ) from e

    def publish(
        self, payload: dict[str, Any], msg_id: Optional[str] = None
    ) -> None:
        """Publish a message to the Azure Event Hub.

        If dynamic_topic is enabled, creates the Event Hub before publishing.
        Ensures proper resource cleanup of the Event Hub client.

        Args:
            payload: The message payload to publish.
            msg_id: Optional message identifier. If not provided,
                generates a UUID.

        Raises:
            ProducerException: If message publishing fails.
        """
        try:
            if self.inputs.get("dynamic_topic", False):
                self._create_topic()

            producer = EventHubProducerClient(
                fully_qualified_namespace=self.inputs["namespace"],
                eventhub_name=self.topic,
                credential=self._get_credential(),
            )
            try:
                batch = producer.create_batch()
                event_data = EventData(json.dumps(payload))
                message_id = msg_id or str(uuid.uuid4())
                event_data.message_id = message_id
                batch.add(event_data)
                producer.send_batch(batch)
                LOGGER.info(
                    "Successfully sent message %s to Event Hub '%s'",
                    message_id,
                    self.topic,
                )
            finally:
                producer.close()

        except Exception as e:
            LOGGER.error("Error sending Azure Event Hub Message %s", str(e))
            raise ProducerException(
                "Error sending message on Azure Event Hub"
            ) from e

    def delete_queues(self) -> None:
        """Azure Event Hub topics and consumer groups are managed externally.

        No cleanup needed as Azure handles Event Hub lifecycle independently.
        """
        pass
