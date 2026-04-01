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
import ssl
import tempfile
import uuid
from pathlib import Path
from typing import Any, Optional

from kafka import KafkaProducer as KafkaProducerClient

from .exceptions import ProducerException
from .interfaces import MessageProducer, hash_activation_name

# Maps user-friendly strings to SSL constants
SSL_VERIFY_MAP = {
    "none": ssl.CERT_NONE,
    "optional": ssl.CERT_OPTIONAL,
    "required": ssl.CERT_REQUIRED,
}

LOGGER = logging.getLogger(__name__)


class KafkaProducer(MessageProducer):
    REVERSE_MAP_EXTRA_VARS = {
        "bootstrap_servers": "{{ kafka_pubsub_bootstrap_servers }}",
        "host": "{{ kafka_pubsub_host }}",
        "port": "{{ kafka_pubsub_port }}",
        "topic": "{{ kafka_pubsub_topic }}",
        "offset": "{{ kafka_pubsub_offset }}",
        "group_id": "{{ kafka_pubsub_group_id }}",
        "verify_mode": "{{ kafka_pubsub_verify_mode }}",
        "check_hostname": "{{ kafka_pubsub_check_hostname }}",
        "sasl_mechanism": "{{ kafka_pubsub_sasl_mechanism }}",
        "security_protocol": "{{ kafka_pubsub_security_protocol }}",
        "sasl_plain_password": "{{ kafka_pubsub_sasl_plain_password }}",
        "sasl_plain_username": "{{ kafka_pubsub_sasl_plain_username }}",
        "cafile": "{{ eda.filename.kafka_pubsub_cafile | default(None) }}",
        "certfile": "{{ eda.filename.kafka_pubsub_certfile | default(None) }}",
        "keyfile": "{{ eda.filename.kafka_pubsub_keyfile | default(None) }}",
        "password": "{{ kafka_pubsub_password | default(None) }}",
        "feedback": "{{ kafka_pubsub_feedback }}",
        "feedback_timeout": "{{ kafka_pubsub_feedback_timeout }}",
    }
    SOURCE_PLUGIN_TYPE = "ansible.eda.kafka"

    def __init__(self, args: dict[str, Any], topic: Optional[str] = None):
        self.inputs = args
        self.bootstrap_servers = None
        self._set_bootstrap()
        if args.get("dynamic_topic", False):
            self.topic = topic or self.inputs.get("topic")
        else:
            self.topic = self.inputs.get("topic")

        if not self.topic:
            raise ValueError("Topic must be specified")

    def _set_bootstrap(self):
        port = int(self.inputs.get("port", 9093))
        if self.inputs.get("bootstrap_servers"):
            self.bootstrap_servers = self.inputs.get("bootstrap_servers")
        elif self.inputs.get("host"):
            self.bootstrap_servers = f"{self.inputs['host']}:{port}"
        else:
            raise ValueError(
                "You must provide either bootstrap_servers or a host."
            )

    def get_consumer_manifest(self, activation_name: str) -> dict:
        local_args = self.__class__.REVERSE_MAP_EXTRA_VARS.copy()
        if self.inputs.get("dynamic_groups", False):
            # Use hashed activation name to avoid exceeding group_id limits
            hashed_name = hash_activation_name(activation_name)
            local_args["group_id"] = f"activation-{hashed_name}"
        local_args["topic"] = self.topic
        local_args["feedback"] = self.inputs.get("feedback", False)

        return {
            "source_type": self.__class__.SOURCE_PLUGIN_TYPE,
            "args": local_args,
        }

    def _create_ssl_context(
        self, temp_dir_name: str
    ) -> Optional[ssl.SSLContext]:
        LOGGER.debug(f"Temporary directory created at: {temp_dir_name}")
        tmp_path = Path(temp_dir_name)
        cafile = keyfile = certfile = None
        if self.inputs.get("cafile"):
            cafile = tmp_path / "cafile"
            with open(cafile, "w") as f:
                f.write(self.inputs["cafile"])
            cafile.chmod(0o600)

        if self.inputs.get("certfile"):
            certfile = tmp_path / "certfile"
            with open(certfile, "w") as f:
                f.write(self.inputs["certfile"])
            certfile.chmod(0o600)

        if self.inputs.get("keyfile"):
            keyfile = tmp_path / "keyfile"
            with open(keyfile, "w") as f:
                f.write(self.inputs["keyfile"])
            keyfile.chmod(0o600)

        # Create context
        if cafile or certfile:
            ssl_context = ssl.create_default_context(
                purpose=ssl.Purpose.SERVER_AUTH,
                cafile=cafile,
            )

            # Load client certificate and key if provided
            if certfile:
                ssl_context.load_cert_chain(
                    certfile=certfile,
                    keyfile=keyfile,
                    password=self.inputs.get("password", None),
                )

            ssl_context.check_hostname = self.inputs.get(
                "check_hostname", True
            )
            verify_mode = self.inputs.get("verify_mode", "required")
            if isinstance(verify_mode, str):
                ssl_context.verify_mode = SSL_VERIFY_MAP.get(
                    verify_mode.lower(), ssl.CERT_REQUIRED
                )
            else:
                ssl_context.verify_mode = ssl.CERT_REQUIRED
            return ssl_context

        return None

    def publish(self, payload: dict, msg_id: Optional[str]) -> None:
        try:
            with tempfile.TemporaryDirectory() as temp_dir_name:
                ssl_context = self._create_ssl_context(temp_dir_name)

                producer = KafkaProducerClient(
                    bootstrap_servers=self.bootstrap_servers,
                    security_protocol=self.inputs.get("security_protocol"),
                    sasl_mechanism=self.inputs.get("sasl_mechanism"),
                    sasl_plain_username=self.inputs.get("sasl_plain_username"),
                    sasl_plain_password=self.inputs.get("sasl_plain_password"),
                    value_serializer=lambda x: json.dumps(x).encode("utf-8"),
                    ssl_context=ssl_context,
                )
                msg_uuid = msg_id or str(uuid.uuid4())
                headers = [
                    ("message_uuid", msg_uuid.encode("utf-8")),
                    ("content_type", b"application/json"),
                ]
                try:
                    LOGGER.debug("Publishing to topic: %s", self.topic)
                    future = producer.send(
                        self.topic, payload, headers=headers
                    )
                    # Wait for the message to be sent
                    future.get(timeout=30)
                finally:
                    producer.close()
        except Exception as e:
            LOGGER.error("Error sending Kafka Message %s", str(e))
            raise ProducerException("Error sending message on Kafka") from e

    def delete_queues(self) -> None:
        """Kafka topics and consumer groups are managed externally.

        No cleanup needed as Kafka handles topic lifecycle independently.
        """
        pass
