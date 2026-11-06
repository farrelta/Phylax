FROM zeek/zeek@sha256:524cb0ce29f26a6a954fb9c357a8f92b95812476d8240f0ece26617ace249dd0
COPY demo /opt/lab
RUN python3 /opt/lab/fetch_dependency.py
ENV PYTHONPATH=/opt/lab/vendor PYTHONDONTWRITEBYTECODE=1 PHYLAX_LAB_ONLY=1
WORKDIR /opt/lab
ENTRYPOINT ["python3", "/opt/lab/lab.py"]
