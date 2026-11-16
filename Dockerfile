FROM python:3.14-slim

LABEL org.opencontainers.image.title="arpwatchdog" \
      org.opencontainers.image.description="Passive ARP spoofing detector" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /arpwatchdog
COPY . .
RUN pip install --no-cache-dir '.[live]' \
 && rm -rf /root/.cache

# Passive-only tool: grant NET_RAW at runtime, e.g.
#   docker run --cap-add=NET_RAW --network=host arpwatchdog -i eth0
USER 65534:65534
ENTRYPOINT ["arpwatchdog"]
CMD ["--help"]
