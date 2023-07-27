# create network
# docker network create distributed-honeypot

docker run -i -d \
    -p 8001:80 \
    --network distributed-honeypot \
    --name honeypot-1 \
    -v ~/log/honeypot/1/:/honeypots/logs \
    justsky/honeypots --setup http

# create second honeypot
docker run -i -d \
    -p 8002:80 \
    --network distributed-honeypot \
    --name honeypot-2 \
    -v ~/log/honeypot/2/:/honeypots/logs \
    justsky/honeypots --setup http