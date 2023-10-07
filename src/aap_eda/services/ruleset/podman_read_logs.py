#  Copyright 2023 Red Hat, Inc.
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
import os
from datetime import datetime

from podman import PodmanClient
from podman.errors.exceptions import APIError

from aap_eda.core import models
from aap_eda.core.enums import ActivationStatus

from .activation_db_logger import ActivationDbLogger

logger = logging.getLogger(__name__)


class PodmanReadLogs:
    def __init__(
        self,
        podman_url: str,
        activation_db_logger: ActivationDbLogger,
    ) -> None:
        if podman_url:
            self.podman_url = podman_url
        else:
            self._default_podman_url()
        logger.info(f"Using podman socket: {self.podman_url}")

        self.client = PodmanClient(base_url=self.podman_url)
        logger.info(self.client.version())
        self.activation_db_logger = activation_db_logger

    def run(
        self,
        activation_instance: models.ActivationInstance,
    ) -> None:
        container_id = activation_instance.activation_pod_id
        try:
            if activation_instance.log_read_at:
                since = int(activation_instance.log_read_at.timestamp()) + 1
            else:
                start_dt = "2000-01-01T00:00:00-00:00"
                since = (
                    int(
                        datetime.strptime(
                            start_dt, "%Y-%m-%dT%H:%M:%S%z"
                        ).timestamp()
                    )
                    + 1
                )

            if self.client.containers.exists(container_id):
                container = self.client.containers.get(container_id)
                if container.status in ["running", "exited", "stopped"]:
                    log_args = {"timestamps": True, "since": since}
                    dt = None
                    for log in container.logs(**log_args):
                        log = log.decode("utf-8")
                        dt = log.split()[0]
                        self.activation_db_logger.write(log)

                    if dt:
                        since = datetime.strptime(dt, "%Y-%m-%dT%H:%M:%S%z")

                    self.activation_db_logger.flush()
                    activation_instance.log_read_at = dt
                    activation_instance.status = ActivationStatus.STOPPED
                    activation_instance.save(update_fields=["log_read_at"])
            else:
                logger.warning(f"Container {container_id} not found.")
                self.activation_db_logger.write(
                    f"Container {container_id} not found.", True
                )
        except APIError as e:
            logger.exception(
                "Failed to fetch container logs: "
                f"{container_id}; error: {str(e)}"
            )
            raise

    def _default_podman_url(self) -> None:
        if os.getuid() == 0:
            self.podman_url = "unix:///run/podman/podman.sock"
        else:
            xdg_runtime_dir = os.getenv(
                "XDG_RUNTIME_DIR", f"/run/user/{os.getuid()}"
            )
            self.podman_url = f"unix://{xdg_runtime_dir}/podman/podman.sock"
