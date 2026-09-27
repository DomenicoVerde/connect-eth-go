.PHONY: all build endpoints docker-build proxy cleanup clean-containers copylogs ping pingv6 iperf iperfv6 vlan vlanv6 twoclients twoclientsv6

build: proxy endpoints docker-build cleanup

proxy:
	GOOS=linux go build $(if $(RACE),-race) -o proxy/proxy ./proxy

endpoints:
	GOOS=linux go build $(if $(RACE),-race) -o client/client ./client

docker-build:
	openssl req -new -x509 -newkey Ed25519 -keyout proxy/key.pem -out proxy/cert.pem -days 365 -subj "/C=US/ST=State/L=City/O=Organization/OU=Unit/CN=proxy" -nodes
	TESTCASE=build docker compose build

cleanup:
	rm client/client || true
	rm proxy/proxy || true
	rm proxy/key.pem proxy/cert.pem || true

clean-containers:
	docker compose --profile twoclients rm -f client client2 proxy server

# Per-frame logs slow down the proxying loops, limiting the throughput measured by iperf.
iperf iperfv6: export LOG_FRAMES=false

# Testcases run by the client. The v6 variants run the same testcase over IPv6.
ping iperf vlan: clean-containers
	TESTCASE=$@ docker compose --env-file ipv4.env up --exit-code-from client

pingv6 iperfv6 vlanv6: clean-containers
	TESTCASE=$(@:v6=) docker compose --env-file ipv6.env up --exit-code-from client

# client2 fails if it can't ping the server: in that case, all containers are stopped and the test fails.
twoclients: clean-containers
	TESTCASE=$@ docker compose --env-file ipv4.env --profile twoclients up --exit-code-from client

twoclientsv6: clean-containers
	TESTCASE=$(@:v6=) docker compose --env-file ipv6.env --profile twoclients up --exit-code-from client

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
