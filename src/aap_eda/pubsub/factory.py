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

import logging
from functools import lru_cache
from typing import Optional

from django.conf import settings

from aap_eda.core import models
from aap_eda.core.utils.credentials import get_resolved_secrets
from aap_eda.pubsub.azure_event_hub import AzureEventHubProducer
from aap_eda.pubsub.azure_service_bus import AzureServiceBusProducer
from aap_eda.pubsub.exceptions import ProducerException
from aap_eda.pubsub.interfaces import MessageProducer
from aap_eda.pubsub.kafka import KafkaProducer
from aap_eda.pubsub.pgmq import PGMQProducer
from aap_eda.pubsub.postgres import PostgresProducer

LOGGER = logging.getLogger(__name__)

# Registry mapping credential type 'kind' values to their producer classes
PRODUCER_REGISTRY = {
    "kafka": KafkaProducer,
    "azure_event_hub": AzureEventHubProducer,
    "azure_service_bus": AzureServiceBusProducer,
    "pgmq": PGMQProducer,
}

# Default producer for backward compatibility
DEFAULT_PRODUCER = PostgresProducer


def register_producer(kind: str, producer_class: type) -> None:
    """Register a new producer class for a credential kind.

    Args:
        kind: The credential type kind identifier.
        producer_class: The MessageProducer implementation class.
    """
    PRODUCER_REGISTRY[kind] = producer_class
    LOGGER.info(
        "Registered producer %s for kind '%s'", producer_class.__name__, kind
    )


def unregister_producer(kind: str) -> None:
    """Unregister a producer class for a credential kind.

    Args:
        kind: The credential type kind identifier to remove.
    """
    if kind in PRODUCER_REGISTRY:
        PRODUCER_REGISTRY.pop(kind)
        LOGGER.info("Unregistered producer for kind '%s'", kind)
    else:
        LOGGER.warning("Attempted to unregister non-existent kind '%s'", kind)


@lru_cache(maxsize=1)
def get_default_producer_credential() -> Optional[models.EdaCredential]:
    """Retrieve and cache the default system PostgreSQL notify credential.

    Returns:
        The default EdaCredential or None if not found.
    """
    return models.EdaCredential.objects.filter(
        name=settings.DEFAULT_SYSTEM_PG_NOTIFY_CREDENTIAL_NAME
    ).first()


def _select_credential(
    obj: models.EventStream,
    consumer_perspective: bool,
) -> Optional[models.EdaCredential]:
    """Select the appropriate credential based on perspective.

    Args:
        obj: The EventStream object containing credential configuration.
        consumer_perspective: If True, prefer consumer_credential over
            producer_credential before falling back to default.

    Returns:
        The selected EdaCredential or None if not found.
    """
    if consumer_perspective:
        return (
            obj.consumer_credential
            or obj.producer_credential
            or get_default_producer_credential()
        )
    return obj.producer_credential or get_default_producer_credential()


def get_producer(
    obj: models.EventStream, consumer_perspective: bool = False
) -> MessageProducer:
    """Create a message producer based on EventStream configuration.

    Args:
        obj: The EventStream object containing credential configuration.
        consumer_perspective: If True, prefer consumer_credential over
            producer_credential before falling back to default.

    Returns:
        An instantiated MessageProducer implementation.

    Raises:
        ProducerException: If no credential is found, channel_name is missing,
            or producer instantiation fails.
    """
    # Validate channel_name
    if not obj.channel_name:
        LOGGER.error(
            "EventStream id=%s has no channel_name defined",
            obj.id,
        )
        raise ProducerException(
            f"EventStream {obj.id} has no channel_name defined"
        )

    # Select appropriate credential
    credential = _select_credential(obj, consumer_perspective)

    if credential is None:
        LOGGER.error(
            "No credential found for EventStream id=%s, channel=%s, "
            "consumer_perspective=%s",
            obj.id,
            obj.channel_name,
            consumer_perspective,
        )
        raise ProducerException(
            f"No credential found for EventStream {obj.id} "
            f"(channel: {obj.channel_name})"
        )

    # Resolve credential secrets
    inputs = get_resolved_secrets(credential)

    # Get the credential type kind and look up the producer class
    credential_kind = credential.credential_type.kind

    # Get producer class from registry, or use default for
    # backward compatibility
    producer_class = PRODUCER_REGISTRY.get(credential_kind)

    if producer_class is None:
        # For backward compatibility, use default producer (Postgres)
        # This handles kind="cloud" and any other non-Kafka types
        LOGGER.debug(
            "Using default producer (%s) for credential kind '%s' "
            "(credential_id=%s, event_stream_id=%s)",
            DEFAULT_PRODUCER.__name__,
            credential_kind,
            credential.id,
            obj.id,
        )
        producer_class = DEFAULT_PRODUCER
        # Postgres uses system-level DSN settings, not credential inputs
        inputs = {}

    # Dynamically instantiate the appropriate producer class
    try:
        LOGGER.info(
            "Creating %s producer for EventStream id=%s, channel=%s",
            producer_class.__name__,
            obj.id,
            obj.channel_name,
        )
        producer_obj = producer_class(inputs, obj.channel_name)
    except Exception as exc:
        LOGGER.error(
            "Failed to instantiate producer %s for credential kind %s: %s",
            producer_class.__name__,
            credential_kind,
            exc,
        )
        raise ProducerException(
            f"Failed to create {producer_class.__name__}: {exc}"
        ) from exc

    return producer_obj
