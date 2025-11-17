FROM ubuntu:latest

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && \
    apt-get install -y socat && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash ctfuser && \
    chown -R ctfuser:ctfuser /home/ctfuser

WORKDIR /home/ctfuser

RUN mkdir -p /home/ctfuser/files && \
    chown -R ctfuser:ctfuser /home/ctfuser/files

USER ctfuser

EXPOSE 7331

CMD ["/bin/bash"]
