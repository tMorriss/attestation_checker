# pull docker images
sudo podman pull python:latest

# build docker image
sudo podman build -t tmorriss/attestation_checker -f ./build/Dockerfile ./

# stop container
count=`sudo podman ps |grep attestation_checker |wc -l`
if [ $count -gt 0 ]; then
  sudo podman stop attestation_checker
fi
# remove container
count=`sudo podman ps -a |grep attestation_checker |wc -l`
if [ $count -gt 0 ]; then
  sudo podman rm attestation_checker
fi

# deploy container
sudo podman run \
-d \
--restart=always \
-p 8010:8010 \
-h attestation_checker \
--name attestation_checker \
tmorriss/attestation_checker

# delete old images
sudo podman image prune -f
