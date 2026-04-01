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

from .exceptions import ProducerException
from .factory import get_default_producer_credential, get_producer
from .interfaces import MessageProducer

__all__ = [
    # Public API - Interface and Exception
    "MessageProducer",
    "ProducerException",
    # Public API - Factory functions (recommended way to create producers)
    "get_producer",
    "get_default_producer_credential",
]

# Note: KafkaProducer and PostgresProducer are intentionally not exported
# in the public API. Use get_producer() factory function instead to obtain
# producer instances. This encapsulates implementation details and allows
# the factory to manage producer instantiation based on credential types.
