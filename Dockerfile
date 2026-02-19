# HorizOS Dockerfile
# This Dockerfile creates an image from the custom rootfs

FROM scratch
ADD horiz-rootfs.tar.gz /

USER horiz

CMD ["/bin/sh"]
