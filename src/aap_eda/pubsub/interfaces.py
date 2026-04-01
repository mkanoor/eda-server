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
import hashlib
from typing import Any, Optional, Protocol, runtime_checkable


def hash_activation_name(activation_name: str) -> str:
    """Hash activation name to a 6-byte (12 hex char) string.

    This ensures that topic/queue names don't exceed length limits in
    various PubSub implementations when combined with EventStream UUID.

    Combined length: UUID(32) + underscore(1) + hash(12) = 45 chars < 48 limit

    Args:
        activation_name: The name of the activation.

    Returns:
        A 12-character hexadecimal string (6 bytes).
    """
    hash_obj = hashlib.sha256(activation_name.encode("utf-8"))
    return hash_obj.hexdigest()[:12]


@runtime_checkable
class MessageProducer(Protocol):
    """Interface for any PubSub provider.

    Includes local production and remote consumer configuration.
    """

    def publish(
        self, payload: dict[str, Any], msg_id: Optional[str] = None
    ) -> None:
        """Send a message to the specified topic.

        Args:
            payload: The message payload to publish.
            msg_id: Optional message identifier. If not provided,
                implementations should generate one.
        """
        ...

    def get_consumer_manifest(self, activation_name: str) -> dict[str, Any]:
        """Generate the configuration dictionary.

        Generate the configuration dictionary required to spawn a consumer
        for this provider on a remote node.

        Args:
            activation_name: The name of the activation (not yet saved to DB).

        Returns:
            A dictionary containing source_type and args for the consumer.
        """
        ...

    def delete_queues(self) -> None:
        """Delete all queues/topics associated with this producer.

        Optional cleanup method called when the EventStream is deleted.
        Implementations should remove all queues, topics, or consumer groups
        created for this EventStream.

        Default behavior: no-op (providers like Kafka/Azure handle cleanup
        automatically or don't require it).
        """
        ...
