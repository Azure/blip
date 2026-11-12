# Alpine guest root for the e2e test (hack/e2e/run.sh). There is no init
# system: Blips boot it with spec.init [/sbin/blip-e2e-init, MODE, ...]
# (see blip-e2e-init). Built from the repository root after `make build`:
#   docker build -f images/blip-e2e/Dockerfile .
FROM alpine:3.20
RUN apk add --no-cache curl jq socat dosfstools e2fsprogs \
 && rm -f /etc/hostname /etc/machine-id
COPY bin/blip-meta /usr/local/bin/blip-meta
COPY images/blip-e2e/lib.sh /usr/lib/blip-e2e/lib.sh
COPY images/blip-e2e/udhcpc.script /usr/lib/blip-e2e/udhcpc.script
COPY --chmod=0755 images/blip-e2e/blip-e2e-init /sbin/blip-e2e-init
RUN chmod 0755 /usr/lib/blip-e2e/udhcpc.script /usr/local/bin/blip-meta
CMD ["/sbin/blip-e2e-init", "ok"]
