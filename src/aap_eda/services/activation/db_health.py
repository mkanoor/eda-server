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
"""Database health monitoring for activation management."""

import logging
from dataclasses import dataclass
from typing import Optional

from django.conf import settings
from django.db import connection

LOGGER = logging.getLogger(__name__)


@dataclass
class DiskSpaceInfo:
    """Information about database disk space usage."""

    database_name: str
    size_pretty: str
    usage_percent: float
    is_critical: bool
    threshold_percent: float


class DatabaseHealthMonitor:
    """Monitor database health for activation lifecycle decisions."""

    @staticmethod
    def check_disk_space() -> tuple[bool, Optional[str], Optional[DiskSpaceInfo]]:
        """
        Check if database has sufficient disk space.

        Returns:
            tuple: (is_critical, error_message, disk_info)
                - is_critical: True if disk space is critically low
                - error_message: Human-readable error message if critical
                - disk_info: DiskSpaceInfo object with details (or None if check disabled/failed)
        """
        if not getattr(settings, "DB_DISK_SPACE_CHECK_ENABLED", True):
            return False, None, None

        try:
            threshold = getattr(settings, "DB_DISK_SPACE_THRESHOLD_PERCENT", 90)

            with connection.cursor() as cursor:
                # Query PostgreSQL for disk usage
                cursor.execute("""
                    SELECT
                        current_database() AS db_name,
                        pg_size_pretty(pg_database_size(current_database())) AS size,
                        ROUND(
                            (pg_database_size(current_database())::float /
                             NULLIF(pg_tablespace_size('pg_default')::float, 0) * 100)::numeric,
                            2
                        ) AS usage_percent
                """)
                row = cursor.fetchone()

                if row:
                    db_name, size_pretty, usage_percent = row

                    # Handle None usage_percent (can happen if tablespace size is 0)
                    if usage_percent is None:
                        LOGGER.warning("Could not calculate database usage percent")
                        return False, None, None

                    usage_float = float(usage_percent)
                    is_critical = usage_float >= threshold

                    disk_info = DiskSpaceInfo(
                        database_name=db_name,
                        size_pretty=size_pretty,
                        usage_percent=usage_float,
                        is_critical=is_critical,
                        threshold_percent=threshold,
                    )

                    if is_critical:
                        retry_seconds = getattr(
                            settings, "DB_DISK_SPACE_RETRY_SECONDS", 1800
                        )
                        retry_minutes = retry_seconds // 60

                        msg = (
                            f"DATABASE NEARING FULL CAPACITY: {usage_float:.1f}% used "
                            f"(critical threshold: {threshold}%). Current database size: {size_pretty}. "
                            f"\n\n"
                            f"ACTIVATIONS HAVE BEEN STOPPED to prevent loss of events and avoid "
                            f"worsening the database capacity problem. The normal restart policy "
                            f"has been SUSPENDED to account for this database space issue. "
                            f"\n\n"
                            f"This activation will remain stopped for {retry_minutes} minutes to allow "
                            f"system administrators to free up database space. After {retry_minutes} minutes, "
                            f"an automatic retry will be attempted. If database space is still insufficient, "
                            f"the activation will stop again and wait another {retry_minutes} minutes. "
                            f"\n\n"
                            f"ACTION REQUIRED: System administrators must free up database space by:\n"
                            f"- Archiving or deleting old audit records\n"
                            f"- Expanding database storage capacity\n"
                            f"- Reducing the number of concurrent activations"
                        )
                        return True, msg, disk_info

                    return False, None, disk_info

            return False, None, None

        except Exception as e:
            LOGGER.warning(f"Failed to check database disk space: {e}", exc_info=True)
            # Don't stop activation if check fails - fail open
            return False, None, None

    @staticmethod
    def get_retry_delay_seconds() -> int:
        """Get the configured retry delay for disk space issues."""
        return getattr(settings, "DB_DISK_SPACE_RETRY_SECONDS", 1800)

    @staticmethod
    def log_disk_space_info(disk_info: Optional[DiskSpaceInfo]) -> None:
        """Log disk space information for monitoring/debugging."""
        if disk_info:
            status = "CRITICAL" if disk_info.is_critical else "OK"
            LOGGER.info(
                f"Database disk space check: {status} - "
                f"Database: {disk_info.database_name}, "
                f"Size: {disk_info.size_pretty}, "
                f"Usage: {disk_info.usage_percent:.1f}%, "
                f"Threshold: {disk_info.threshold_percent}%"
            )
