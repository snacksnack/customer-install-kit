# Default-deny egress proxy for the triage runtime (RC1-643, ADR 0009).
# CONNECT only, port 443 only, to the hosts in `filter` only.
FROM alpine:3.20
RUN apk add --no-cache tinyproxy
COPY tinyproxy.conf /etc/tinyproxy/tinyproxy.conf
COPY filter /etc/tinyproxy/filter
USER tinyproxy
EXPOSE 8888
ENTRYPOINT ["tinyproxy", "-d", "-c", "/etc/tinyproxy/tinyproxy.conf"]
