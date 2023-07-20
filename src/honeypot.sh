# docker network create distributed-honeypot

docker kill $(docker ps -aq) && docker rm $(docker ps -aq)

docker run -i -d \
    -p 8001:80 \
    --network distributed-honeypot \
    --name honeypot-1 \
    -v ~/log/honeypot/1/:/honeypots/logs \
    justsky/honeypots --setup http

docker run -i -d \
    -p 8002:80 \
    --network distributed-honeypot \
    --name honeypot-2 \
    -v ~/log/honeypot/2/:/honeypots/logs \
    justsky/honeypots --setup http