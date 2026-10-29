# Copyright (c) 2026 Sawan Bhan. All rights reserved. Licensed under the MIT License.
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /opt/sawone-red
COPY pyproject.toml README.md LICENSE ./
COPY sawone_red ./sawone_red
RUN pip install --no-cache-dir .

COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
