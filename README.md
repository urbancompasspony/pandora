## pandora
A new and freshed one! Docker only.

MULTIARCH

docker buildx create --name mybuilder

docker buildx use mybuilder

docker login registry.gitlab.com

docker buildx build --push --platform linux/amd64,linux/arm64 --tag registry.gitlab.com/docker329/pentest:latest .

# On Android - SSH Button

Set DateTime

echo "aaa" | sudo -S systemctl restart systemd-timesyncd.service

Start Pentesting:

docker exec pentest-host bash ./pandora.sh &

Shutdown

echo "aaa" | sudo -S shutdown -h now
