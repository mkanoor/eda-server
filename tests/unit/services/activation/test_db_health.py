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
"""Tests for DatabaseHealthMonitor."""

from unittest.mock import MagicMock, patch

import pytest

from aap_eda.services.activation.db_health import (
    DatabaseHealthMonitor,
    DiskSpaceInfo,
)


@pytest.fixture
def mock_cursor():
    """Create a mock cursor."""
    cursor = MagicMock()
    return cursor


class TestDatabaseHealthMonitor:
    """Test DatabaseHealthMonitor class."""

    def test_check_disk_space_disabled(self, settings):
        """Test disk space check when disabled in settings."""
        settings.DB_DISK_SPACE_CHECK_ENABLED = False

        is_critical, error_msg, disk_info = (
            DatabaseHealthMonitor.check_disk_space()
        )

        assert is_critical is False
        assert error_msg is None
        assert disk_info is None

    @patch("aap_eda.services.activation.db_health.connection")
    def test_check_disk_space_below_threshold(self, mock_connection, settings):
        """Test disk space check when usage is below threshold."""
        settings.DB_DISK_SPACE_CHECK_ENABLED = True
        settings.DB_DISK_SPACE_THRESHOLD_PERCENT = 90

        # Mock cursor with data showing 50% usage (below threshold)
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ("test_db", "500 MB", 50.0)
        mock_connection.cursor.return_value.__enter__.return_value = (
            mock_cursor
        )

        is_critical, error_msg, disk_info = (
            DatabaseHealthMonitor.check_disk_space()
        )

        assert is_critical is False
        assert error_msg is None
        assert disk_info is not None
        assert disk_info.database_name == "test_db"
        assert disk_info.size_pretty == "500 MB"
        assert disk_info.usage_percent == 50.0
        assert disk_info.is_critical is False
        assert disk_info.threshold_percent == 90

    @patch("aap_eda.services.activation.db_health.connection")
    def test_check_disk_space_above_threshold(self, mock_connection, settings):
        """Test disk space check when usage is above threshold."""
        settings.DB_DISK_SPACE_CHECK_ENABLED = True
        settings.DB_DISK_SPACE_THRESHOLD_PERCENT = 90
        settings.DB_DISK_SPACE_RETRY_SECONDS = 1800

        # Mock cursor with data showing 95% usage (above threshold)
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ("test_db", "950 MB", 95.0)
        mock_connection.cursor.return_value.__enter__.return_value = (
            mock_cursor
        )

        is_critical, error_msg, disk_info = (
            DatabaseHealthMonitor.check_disk_space()
        )

        assert is_critical is True
        assert error_msg is not None
        assert "DATABASE NEARING FULL CAPACITY" in error_msg
        assert "95.0% used" in error_msg
        assert "critical threshold: 90%" in error_msg
        assert "30 minutes" in error_msg  # 1800 seconds = 30 minutes
        assert disk_info is not None
        assert disk_info.is_critical is True
        assert disk_info.usage_percent == 95.0

    @patch("aap_eda.services.activation.db_health.connection")
    def test_check_disk_space_exactly_at_threshold(
        self, mock_connection, settings
    ):
        """Test disk space check when usage equals threshold."""
        settings.DB_DISK_SPACE_CHECK_ENABLED = True
        settings.DB_DISK_SPACE_THRESHOLD_PERCENT = 90

        # Mock cursor with data showing exactly 90% usage
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ("test_db", "900 MB", 90.0)
        mock_connection.cursor.return_value.__enter__.return_value = (
            mock_cursor
        )

        is_critical, error_msg, disk_info = (
            DatabaseHealthMonitor.check_disk_space()
        )

        # At threshold should be considered critical
        assert is_critical is True
        assert error_msg is not None
        assert disk_info.is_critical is True

    @patch("aap_eda.services.activation.db_health.connection")
    def test_check_disk_space_none_usage(self, mock_connection, settings):
        """Test disk space check when usage_percent is None."""
        settings.DB_DISK_SPACE_CHECK_ENABLED = True

        # Mock cursor returning None for usage_percent
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ("test_db", "500 MB", None)
        mock_connection.cursor.return_value.__enter__.return_value = (
            mock_cursor
        )

        is_critical, error_msg, disk_info = (
            DatabaseHealthMonitor.check_disk_space()
        )

        assert is_critical is False
        assert error_msg is None
        assert disk_info is None

    @patch("aap_eda.services.activation.db_health.connection")
    def test_check_disk_space_no_row_returned(self, mock_connection, settings):
        """Test disk space check when cursor returns no row."""
        settings.DB_DISK_SPACE_CHECK_ENABLED = True

        # Mock cursor returning None
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = None
        mock_connection.cursor.return_value.__enter__.return_value = (
            mock_cursor
        )

        is_critical, error_msg, disk_info = (
            DatabaseHealthMonitor.check_disk_space()
        )

        assert is_critical is False
        assert error_msg is None
        assert disk_info is None

    @patch("aap_eda.services.activation.db_health.connection")
    def test_check_disk_space_exception(self, mock_connection, settings):
        """Test disk space check handles exceptions gracefully (fail open)."""
        settings.DB_DISK_SPACE_CHECK_ENABLED = True

        # Mock cursor raising exception
        mock_connection.cursor.side_effect = Exception("Database error")

        is_critical, error_msg, disk_info = (
            DatabaseHealthMonitor.check_disk_space()
        )

        # Should fail open - don't stop activation on check failure
        assert is_critical is False
        assert error_msg is None
        assert disk_info is None

    def test_get_retry_delay_seconds_default(self):
        """Test get_retry_delay_seconds returns default."""
        # No setting configured
        delay = DatabaseHealthMonitor.get_retry_delay_seconds()
        assert delay == 1800  # Default

    def test_get_retry_delay_seconds_custom(self, settings):
        """Test get_retry_delay_seconds returns configured value."""
        settings.DB_DISK_SPACE_RETRY_SECONDS = 3600

        delay = DatabaseHealthMonitor.get_retry_delay_seconds()
        assert delay == 3600

    def test_log_disk_space_info_none(self, caplog):
        """Test log_disk_space_info with None disk_info."""
        DatabaseHealthMonitor.log_disk_space_info(None)

        # Should not log anything
        assert len(caplog.records) == 0

    @patch("aap_eda.services.activation.db_health.LOGGER")
    def test_log_disk_space_info_ok_status(self, mock_logger):
        """Test log_disk_space_info with OK status."""
        disk_info = DiskSpaceInfo(
            database_name="test_db",
            size_pretty="500 MB",
            usage_percent=50.0,
            is_critical=False,
            threshold_percent=90,
        )

        DatabaseHealthMonitor.log_disk_space_info(disk_info)

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "Database disk space check: OK" in call_args
        assert "Database: test_db" in call_args
        assert "Size: 500 MB" in call_args
        assert "Usage: 50.0%" in call_args
        assert "Threshold: 90%" in call_args

    @patch("aap_eda.services.activation.db_health.LOGGER")
    def test_log_disk_space_info_critical_status(self, mock_logger):
        """Test log_disk_space_info with CRITICAL status."""
        disk_info = DiskSpaceInfo(
            database_name="test_db",
            size_pretty="950 MB",
            usage_percent=95.0,
            is_critical=True,
            threshold_percent=90,
        )

        DatabaseHealthMonitor.log_disk_space_info(disk_info)

        mock_logger.info.assert_called_once()
        call_args = mock_logger.info.call_args[0][0]
        assert "Database disk space check: CRITICAL" in call_args
        assert "Usage: 95.0%" in call_args

    @patch("aap_eda.services.activation.db_health.connection")
    def test_check_disk_space_custom_threshold(
        self, mock_connection, settings
    ):
        """Test disk space check with custom threshold."""
        settings.DB_DISK_SPACE_CHECK_ENABLED = True
        settings.DB_DISK_SPACE_THRESHOLD_PERCENT = 80

        # Mock cursor with data showing 85% usage (above custom threshold)
        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ("test_db", "850 MB", 85.0)
        mock_connection.cursor.return_value.__enter__.return_value = (
            mock_cursor
        )

        is_critical, error_msg, disk_info = (
            DatabaseHealthMonitor.check_disk_space()
        )

        assert is_critical is True
        assert "critical threshold: 80%" in error_msg
        assert disk_info.threshold_percent == 80

    @patch("aap_eda.services.activation.db_health.connection")
    def test_check_disk_space_error_message_content(
        self, mock_connection, settings
    ):
        """Test that error message contains all required information."""
        settings.DB_DISK_SPACE_CHECK_ENABLED = True
        settings.DB_DISK_SPACE_THRESHOLD_PERCENT = 90
        settings.DB_DISK_SPACE_RETRY_SECONDS = 1800

        mock_cursor = MagicMock()
        mock_cursor.fetchone.return_value = ("test_db", "950 MB", 95.0)
        mock_connection.cursor.return_value.__enter__.return_value = (
            mock_cursor
        )

        is_critical, error_msg, disk_info = (
            DatabaseHealthMonitor.check_disk_space()
        )

        # Verify all required content in error message
        assert "DATABASE NEARING FULL CAPACITY" in error_msg
        assert "ACTIVATIONS HAVE BEEN STOPPED" in error_msg
        assert "normal restart policy" in error_msg
        assert "has been SUSPENDED" in error_msg
        assert "ACTION REQUIRED" in error_msg
        assert "Archiving or deleting old audit records" in error_msg
        assert "Expanding database storage capacity" in error_msg
        assert "Reducing the number of concurrent activations" in error_msg
