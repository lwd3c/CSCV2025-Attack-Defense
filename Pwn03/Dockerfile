FROM ubuntu:22.04

RUN apt-get update -y && apt-get install -y socat gcc make libssl-dev ca-certificates build-essential

RUN useradd -d /home/icon -m -p icon -s /bin/bash icon
RUN echo "icon:icon" | chpasswd

WORKDIR /home/icon

COPY chall chall
RUN mkdir -p /tmp/storage/admin
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh


RUN chown -R root:icon /home/icon
RUN chmod 2755 ./chall
RUN chmod 777 /tmp/storage
RUN chown -R root:icon /tmp/storage/admin


EXPOSE 3636

ENTRYPOINT ["/entrypoint.sh"]
