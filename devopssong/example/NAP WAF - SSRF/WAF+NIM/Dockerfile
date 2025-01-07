FROM YOUR_REGISRTY:npic-3.7.0

USER root

RUN apt-get update && apt-get install -y \
    curl \
    gnupg \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN curl -fsSL https://github.com/nginx/agent/releases/download/v2.39.0/nginx-agent-2.39.0.bookworm_amd64.deb -o /tmp/nginx-agent.deb && \
    dpkg -i /tmp/nginx-agent.deb && \
    rm -f /tmp/nginx-agent.deb

RUN touch /var/lib/nginx-agent/agent-dynamic.conf && chown nginx:nginx /var/lib/nginx-agent/agent-dynamic.conf

USER nginx

CMD ["nginx-agent"]