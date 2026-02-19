# HorizOS Dockerfile
# This Dockerfile creates an image from the custom rootfs

FROM scratch
ADD horiz-rootfs.tar.gz /

CMD ["/bin/sh"]
