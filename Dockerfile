# HorizOS Dockerfile
# This Dockerfile creates an image from the custom rootfs

FROM scratch
ADD horizos-rootfs.tar.gz /

CMD ["/bin/sh"]
