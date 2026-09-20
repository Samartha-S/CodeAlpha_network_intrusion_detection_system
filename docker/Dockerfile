FROM jasonish/suricata:latest

ENV SURICATA_INTERFACE=eth0 \
    SURICATA_CONFIG_PATH=/opt/nids/config \
    SURICATA_RULE_PATH=/opt/nids/config/rules \
    SURICATA_LOG_DIR=/var/log/suricata

WORKDIR /opt/nids

COPY config/ /opt/nids/config/

RUN mkdir -p /var/log/suricata /opt/nids/alerts /opt/nids/logs

RUN ln -sf /opt/nids/config/suricata.yaml /etc/suricata/suricata.yaml && \
    ln -sf /opt/nids/config/classification.config /etc/suricata/classification.config && \
    ln -sf /opt/nids/config/reference.config /etc/suricata/reference.config && \
    ln -sf /opt/nids/config/threshold.config /etc/suricata/threshold.config && \
    cp /opt/nids/config/rules/*.rules /etc/suricata/rules/ 2>/dev/null || true && \
    suricata -T -c /opt/nids/config/suricata.yaml

COPY scripts/ /opt/nids/scripts/

RUN chmod +x /opt/nids/scripts/*.sh /opt/nids/scripts/*.py

EXPOSE 5001

CMD ["suricata", "-c", "/opt/nids/config/suricata.yaml", "-i", "eth0", "-l", "/var/log/suricata"]
