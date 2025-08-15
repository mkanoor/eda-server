#  Copyright 2025 Red Hat, Inc.
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
"""Module to send data to activations via PGMQ."""
import logging

import asyncpg
from asyncpg.exceptions import PostgresError
from tembo_pgmq_python.async_queue import PGMQueue

LOGGER = logging.getLogger(__name__)


class PGMQProducer:
    def __init__(self, **kwargs):
        self.connect_args = kwargs
        self.dsn = self._get_dsn()

    def _get_dsn(self):
        result = (
            f"postgres://{self.connect_args['host']}:"
            f"{self.connect_args['port']}"
            f"/{self.connect_args['database']}?"
        )
        options = ""
        for key in [
            "sslmode",
            "sslcert",
            "sslkey",
            "sslrootcert",
            "user",
            "password",
        ]:
            if key in self.connect_args and self.connect_args[key]:
                value = self.connect_args[key]
                if options:
                    options += "&"
                options += f"{key}={value}"

        return result + options

    async def send_data(self, queue_name: str, data: dict):
        conn = None
        try:
            conn = await asyncpg.connect(dsn=self.dsn)

            pgmq_queue = PGMQueue()
            await pgmq_queue.create_queue(queue_name, conn=conn)
            await pgmq_queue.send(queue_name, data, conn=conn)
        except PostgresError as e:
            LOGGER.exception(f"Postgres Error {str(e)}")
            raise
        finally:
            if conn:
                await conn.close()
