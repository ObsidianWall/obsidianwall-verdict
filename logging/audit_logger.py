# logging/audit_logger.py

# Purpose: Enterprise-grade structured logging + audit trail foundation
# Purpose: Structured audit logging (CRITICAL for compliance)
# Audit Logger for ObsidianWall-Guardrails


import logging
import json
import sys
import uuid
from datetime import datetime


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "event_id": str(uuid.uuid4()),
            "timestamp": datetime.utcnow().isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }

        if hasattr(record, "extra"):
            log_record.update(record.extra)

        return json.dumps(log_record)


def get_logger():
    logger = logging.getLogger("obsidianwall.audit")

    if not logger.handlers:
        logger.setLevel(logging.INFO)

        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(JsonFormatter())

        logger.addHandler(handler)

    return logger