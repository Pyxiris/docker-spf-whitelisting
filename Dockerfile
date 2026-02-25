FROM alpine:latest

RUN apk add --no-cache iptables iproute2 bind-tools ulogd
COPY sync_spf.sh /usr/local/bin/sync_spf.sh
RUN chmod +x /usr/local/bin/sync_spf.sh

# Set defaults (can be overridden by docker-compose)
ENV INCOMING_SMTP_PORT=25
ENV SPF_CHECK_INTERVAL=3600
ENV WHITELISTED_SPF=_spf.google.com
ENV ENABLE_REVERSE_DNS=0
ENV REVERSE_DNS_ROOT_DOMAIN=unverified-forwarding.1e100.net
ENV DNS_SERVER=8.8.8.8
ENV COMMENT_PREFIX="MAILGATE_SPF"
ENV CLEAN_ON_EXIT=1
ENV IP_CACHE_LIMIT=50

ENTRYPOINT ["/usr/local/bin/sync_spf.sh"]