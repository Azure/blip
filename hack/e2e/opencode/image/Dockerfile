# Local end-to-end image for the opencode ACP profile.
#
# Build through hack/e2e/opencode/run.sh, which stages the host's opencode
# binary next to this Dockerfile. The binary is not committed.
FROM localhost:5001/blip/dev:latest

USER root
COPY opencode /usr/local/bin/opencode
RUN chmod 0755 /usr/local/bin/opencode
USER dev
