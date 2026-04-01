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
"""Module to send data to activations via PGMQ with topic-based routing.

Uses PGMQ's native topic routing (send_topic/bind_topic) for broadcast/fanout
to multiple activation queues without manual message duplication.
"""

import asyncio
import json
import logging
import tempfile
from pathlib import Path
from typing import Any, Optional

import asyncpg
from asyncpg.exceptions import PostgresError
from tembo_pgmq_python.async_queue import PGMQueue

from .exceptions import ProducerException
from .interfaces import MessageProducer, hash_activation_name

LOGGER = logging.getLogger(__name__)


class PGMQProducer(MessageProducer):
    PGMQ_DSN = (
        "postgres://{{pgmq_db_user}}:{{pgmq_db_password}}@"
        "{{pgmq_db_host}}:{{pgmq_db_port}}"
        "/{{pgmq_db_name}}?"
        "sslmode={{pgmq_sslmode}}&"
        "sslcert={{eda.filename.pgmq_sslcert|default('')}}&"
        "sslkey={{eda.filename.pgmq_sslkey|default('')}}&"
        "sslrootcert={{eda.filename.pgmq_sslrootcert|default('')}}&"
        "sslpassword={{pgmq_sslpassword|default('')}}"
    )

    SOURCE_PLUGIN_TYPE = "eda.builtin.pgmq_listener"
    MAX_QUEUE_NAME_LENGTH = 48

    def __init__(self, args: dict[str, Any], topic: Optional[str] = None):
        self.inputs = args
        self.routing_key = topic or args.get("queue_name")

        # Strip the EventStream prefix to get clean UUID
        if self.routing_key.startswith("eda_event_stream_"):
            self.routing_key = self.routing_key[17:]

        # Keep routing key with hyphens for readability
        # Topic routing uses this as the routing key pattern
        if not self.routing_key:
            raise ValueError("Routing key (topic) must be specified")

        self.connect_args = args

        # Create default archive queue to preserve events before activations exist
        # This ensures no events are lost during the window between EventStream
        # creation and first activation being attached
        try:
            default_queue = f"archive_{self.routing_key.replace('-', '')[:20]}"
            asyncio.run(self._create_and_bind_queue_async(default_queue))
            LOGGER.info(
                "Created default archive queue '%s' for EventStream routing_key '%s'",
                default_queue,
                self.routing_key,
            )
        except Exception as e:
            LOGGER.warning(
                "Failed to create default archive queue for routing_key '%s': %s",
                self.routing_key,
                e,
            )

    def _get_dsn(self, temp_dir_name: str) -> str:
        """Build DSN from connection arguments."""
        host = self.connect_args.get("postgres_db_host", "localhost")
        port = self.connect_args.get("postgres_db_port", 5432)
        database = self.connect_args.get("postgres_db_name", "postgres")

        tmp_path = Path(temp_dir_name)
        result = f"postgres://{host}:{port}/{database}?"
        options = ""

        for key, attr_name, mode in [
            ("sslmode", "postgres_sslmode", None),
            ("sslcert", "postgres_sslcert", 0o600),
            ("sslkey", "postgres_sslkey", 0o600),
            ("sslrootcert", "postgres_sslrootcert", 0o600),
            ("user", "postgres_db_user", None),
            ("password", "postgres_db_password", None),
        ]:
            if attr_name in self.connect_args and self.connect_args[attr_name]:
                value = self.connect_args[attr_name]
                if mode is not None:
                    filename = tmp_path / attr_name
                    with open(filename, "w") as f:
                        f.write(value)
                    filename.chmod(mode)
                    value = str(filename)

                if options:
                    options += "&"
                options += f"{key}={value}"

        return result + options

    def get_consumer_manifest(self, activation_name: str) -> dict[str, Any]:
        """Generate the configuration dictionary for PGMQ consumer.

        Creates a unique queue for this activation and binds it to the
        EventStream's routing key using PGMQ topic routing.

        IMPORTANT: Creates and binds the queue immediately (server-side) to
        ensure events published before the activation starts are not lost.

        Args:
            activation_name: The name of the activation (not yet saved to DB).

        Returns:
            A dictionary containing source_type and args for the consumer,
            including topic binding information.
        """
        # Create unique queue name for this activation
        # Use hash to keep within 48 char limit
        hashed_name = hash_activation_name(activation_name)
        queue_name = f"act_{hashed_name}"

        # Pre-create and bind queue to ensure no events are lost
        # during activation startup delay
        try:
            asyncio.run(self._create_and_bind_queue_async(queue_name))
            LOGGER.info(
                "Pre-created and bound queue '%s' to routing_key '%s' "
                "for activation '%s'",
                queue_name,
                self.routing_key,
                activation_name,
            )
        except Exception as e:
            LOGGER.error(
                "Failed to pre-create queue '%s' for activation '%s': %s",
                queue_name,
                activation_name,
                e,
            )
            raise ProducerException(
                f"Failed to setup queue for activation '{activation_name}'"
            ) from e

        args = {
            "dsn": self.__class__.PGMQ_DSN,
            "queues": [queue_name],
            "feedback": self.inputs["pgmq_feedback"],
            "visibility_timeout": self.inputs["pgmq_visibility_timeout"],
            # Topic binding info for consumer setup
            "topic_routing_key": self.routing_key,
            "topic_pattern": self.routing_key,  # Exact match pattern
        }

        return {
            "source_type": self.__class__.SOURCE_PLUGIN_TYPE,
            "args": args,
        }

    def publish(
        self, payload: dict[str, Any], msg_id: Optional[str] = None
    ) -> None:
        """Send a message using PGMQ topic routing.

        Uses send_topic() to broadcast to all queues bound to this
        EventStream's routing key. PGMQ handles fanout automatically.

        Args:
            payload: The message payload to publish.
            msg_id: Optional message identifier (not used in PGMQ).
        """
        try:
            asyncio.run(self._send_topic_async(payload))
        except Exception as e:
            LOGGER.error("Error sending PGMQ topic message: %s", str(e))
            raise ProducerException("Error sending PGMQ topic message") from e

    async def _create_and_bind_queue_async(self, queue_name: str) -> None:
        """Create queue and bind it to routing key (server-side).

        This is called during get_consumer_manifest to pre-create and bind
        the queue so events don't get lost during activation startup.

        Args:
            queue_name: The name of the queue to create and bind.
        """
        conn = None
        try:
            with tempfile.TemporaryDirectory() as temp_dir_name:
                conn = await asyncpg.connect(dsn=self._get_dsn(temp_dir_name))
                pgmq_queue = PGMQueue()

                # Create queue (idempotent - won't fail if exists)
                await pgmq_queue.create_queue(queue_name, conn=conn)
                LOGGER.debug(f"Created queue: {queue_name}")

                # Bind queue to topic routing key for fanout
                await conn.execute(
                    "SELECT pgmq.bind_topic($1, $2)",
                    self.routing_key,
                    queue_name,
                )
                LOGGER.debug(
                    f"Bound queue '{queue_name}' to routing_key '{self.routing_key}'"
                )

        except PostgresError as e:
            LOGGER.exception(
                "Postgres Error creating/binding queue '%s': %s",
                queue_name,
                str(e),
            )
            raise
        finally:
            if conn:
                await conn.close()

    async def _send_topic_async(self, data: dict[str, Any]) -> None:
        """Send data using PGMQ topic routing.

        Calls pgmq.send_topic() which broadcasts to all queues bound to
        the routing key pattern.

        Args:
            data: The data to send.
        """
        conn = None
        try:
            with tempfile.TemporaryDirectory() as temp_dir_name:
                conn = await asyncpg.connect(dsn=self._get_dsn(temp_dir_name))

                # Convert payload to JSON
                payload_json = json.dumps(data)

                # Use pgmq.send_topic() for broadcast
                # This routes to all queues bound to this routing_key
                result = await conn.fetchval(
                    "SELECT pgmq.send_topic($1, $2::jsonb)",
                    self.routing_key,
                    payload_json,
                )

                LOGGER.debug(
                    "Sent message to topic '%s', routed to %s queue(s)",
                    self.routing_key,
                    result if result else 0,
                )
        except PostgresError as e:
            LOGGER.exception("Postgres Error sending topic: %s", str(e))
            raise
        finally:
            if conn:
                await conn.close()

    def delete_queues(self) -> None:
        """Delete all PGMQ queues bound to this EventStream's routing key.

        Finds all topic bindings for this routing_key and deletes the
        associated queues.
        """
        try:
            asyncio.run(self._delete_queues_async())
        except Exception as e:
            LOGGER.error("Error deleting PGMQ queues: %s", str(e))
            raise ProducerException("Error deleting PGMQ queues") from e

    async def _delete_queues_async(self) -> None:
        """Delete all queues bound to this routing key asynchronously.

        Queries pgmq topic bindings to find all queues subscribed to this
        EventStream's routing key, then drops them.
        """
        conn = None
        try:
            with tempfile.TemporaryDirectory() as temp_dir_name:
                conn = await asyncpg.connect(dsn=self._get_dsn(temp_dir_name))

                # Query topic bindings to find queues bound to this routing_key
                # This assumes pgmq stores bindings in a table (adjust if needed)
                bound_queues = await conn.fetch(
                    """
                    SELECT DISTINCT queue_name
                    FROM pgmq.topic_bindings
                    WHERE pattern = $1
                    """,
                    self.routing_key,
                )

                queue_names = [row["queue_name"] for row in bound_queues]

                if queue_names:
                    LOGGER.info(
                        "Deleting %d PGMQ queue(s) bound to routing_key '%s': %s",
                        len(queue_names),
                        self.routing_key,
                        queue_names,
                    )
                    pgmq_queue = PGMQueue()
                    for queue_name in queue_names:
                        await pgmq_queue.drop_queue(queue_name, conn=conn)
                        LOGGER.debug("Dropped PGMQ queue: %s", queue_name)
                else:
                    LOGGER.debug(
                        "No PGMQ queues found for routing_key '%s'",
                        self.routing_key,
                    )

        except PostgresError as e:
            LOGGER.exception(
                "Postgres Error while deleting queues: %s", str(e)
            )
            raise
        finally:
            if conn:
                await conn.close()
