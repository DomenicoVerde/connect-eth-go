.PHONY: all build endpoints docker-build proxy pingtest

build: proxy endpoints docker-build cleanup

proxy:
	GOOS=linux go build $(if $(RACE),-race) -o proxy/proxy ./proxy

endpoints:
	openssl req -new -x509 -newkey Ed25519 -keyout server/key.pem -out server/cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=server" -nodes
	GOOS=linux go build $(if $(RACE),-race) -o server/server ./server
	GOOS=linux go build $(if $(RACE),-race) -o client/client ./client

docker-build:
	openssl req -new -x509 -newkey Ed25519 -keyout proxy/key.pem -out proxy/cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=proxy" -nodes
	TESTCASE=build docker compose build

cleanup:
	rm client/client || true
	rm server/server || true
	rm proxy/proxy || true
	rm server/key.pem server/cert.pem || true
	rm proxy/key.pem proxy/cert.pem || true

clean-containers:
	docker compose rm -f client proxy server

ping: clean-containers
	TESTCASE=ping docker compose --env-file ipv4.env up --exit-code-from client

pingv6: clean-containers
	TESTCASE=ping docker compose --env-file ipv6.env up --exit-code-from client

copylogs:
	if [ -z "$(target)" ]; then echo "target directory not specified"; exit 1; fi
	rm -rf $(target)
	mkdir -p $(target)
	docker compose logs > $(target)/docker-compose.log
	docker cp eth-client:/keys.txt $(target)/
	docker cp eth-client:/client.pcap $(target)/
	docker cp eth-server:/server.pcap $(target)/
	docker cp eth-proxy:/proxy_eth0.pcap $(target)/
	docker cp eth-proxy:/proxy_eth1.pcap $(target)/
