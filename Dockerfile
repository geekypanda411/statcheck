# Optional convenience image for offline/static analysis.
# NOT a security boundary: external tools parse untrusted input - run in a
# disposable VM for real malware. See docs/security.md.
FROM python:3.12-slim

# pefile/lief/yara wheels need build tools on slim images.
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Non-root user.
RUN useradd --create-home --shell /bin/bash statcheck
USER statcheck
WORKDIR /work

COPY --chown=statcheck:statcheck . /opt/statcheck
# Keep /opt/statcheck as the project root so default config/tool/rule paths
# resolve there. The real config is gitignored, so create it from the example.
RUN cp /opt/statcheck/tools_config.json.example /opt/statcheck/tools_config.json \
    && pip install --user --no-cache-dir -e /opt/statcheck
ENV PATH="/home/statcheck/.local/bin:${PATH}"

# Mount your samples and rules:
#   docker run --rm -v "$PWD:/work" -v "/path/to/bin:/opt/statcheck/bin" \
#     -v "/path/to/yara_rules:/opt/statcheck/yara_rules" \
#     statcheck /work/sample.exe --format auto --report json --output-dir /work/reports
ENTRYPOINT ["statcheck"]
CMD ["--help"]
