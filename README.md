MULTIARCH

docker buildx create --name mybuilder

docker buildx use mybuilder

docker login

EXAMPLE

docker buildx build --push --platform linux/amd64,linux/arm64 --tag urbancompasspony/pandora .

docker buildx build --push --platform linux/amd64,linux/arm64 --tag registry.gitlab.com/docker329/pentest:latest .





# pandora
A new and freshed one! Docker only.

## Creating a Docker image of this service!

for AMD64

docker login registry.gitlab.com

docker build -t registry.gitlab.com/docker329/pentest:latest .

for ARM64

docker build -t registry.gitlab.com/docker329/pentest:arm .

THE PUSH

docker push registry.gitlab.com/docker329/pentest:ARCH-HERE

## On Android - SSH Button

Set DateTime

echo "aaa" | sudo -S systemctl restart systemd-timesyncd.service

Start Pentesting:

docker exec pentest-host bash ./pandora.sh &

Shutdown

echo "aaa" | sudo -S shutdown -h now
