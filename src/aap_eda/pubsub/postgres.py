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
from typing import Any, Optional

from django.conf import settings

from aap_eda.services.pg_notify import PGNotify

from .exceptions import ProducerException
from .interfaces import MessageProducer

LOGGER = logging.getLogger(__name__)


class PostgresProducer(MessageProducer):
    PG_NOTIFY_DSN = (
        "host={{postgres_db_host}} port={{postgres_db_port}} "
        "dbname={{postgres_db_name}} user={{postgres_db_user}} "
        "password={{postgres_db_password}} sslmode={{postgres_sslmode}} "
        "sslcert={{eda.filename.postgres_sslcert|default(None)}} "
        "sslkey={{eda.filename.postgres_sslkey|default(None)}} "
        "sslpassword={{postgres_sslpassword|default(None)}} "
        "sslrootcert={{eda.filename.postgres_sslrootcert|default(None)}}"
    )

    SOURCE_PLUGIN_TYPE = "eda.builtin.pg_listener"

    def __init__(self, args: dict[str, Any], topic: Optional[str] = None):
        self.inputs = args
        self.topic = topic
        if not self.topic:
            raise ValueError("Topic must be specified")

    def get_consumer_manifest(self, activation_name: str) -> dict:
        args = {}
        args["dsn"] = self.__class__.PG_NOTIFY_DSN
        args["channels"] = [self.topic]

        return {
            "source_type": self.__class__.SOURCE_PLUGIN_TYPE,
            "args": args,
        }

    def publish(self, payload: dict, msg_id: Optional[str] = None) -> None:
        try:
            PGNotify(
                settings.PG_NOTIFY_DSN_SERVER,
                self.topic,
                payload,
            )()
        except Exception as e:
            LOGGER.error("Error sending PGNotify Message %s", str(e))
            raise ProducerException("Error sending PGNotify Message")

    def delete_queues(self) -> None:
        """Postgres LISTEN/NOTIFY channels don't require cleanup.

        Channels are automatically cleaned up by PostgreSQL.
        """
        pass
