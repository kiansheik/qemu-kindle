#!/bin/bash
brew install qemu

# assumes you have some kindle rootfs.img update file in $PWD/kindlos/rootfs.img

# https://packages.debian.org/trixie/linux-image-armmp Download the kernel and dtb files from here
PATH_OF_KERNEL_DEB="/Users/kian/Downloads/linux-image-6.12.48+deb13-armmp_6.12.48-1_armhf.deb"

rm -f build/kindle-rootfs.ext4
cd build
# optional, if you want to have custom fonts mapped to /mnt/fonts, necessary for my app at least
mkdir -p fonts
mkdir -p armmp
cd armmp
dpkg-deb --extract "$PATH_OF_KERNEL_DEB" .
cd ../../
dd if=/dev/zero of=build/kindle-rootfs.ext4 bs=1M count=2048
mke2fs -t ext4 build/kindle-rootfs.ext4

docker run --rm --privileged --platform linux/arm/v7 \
  -v "$PWD":/work \
  -v "$PWD/kindlos/rootfs.img":/src/rootfs.img:ro \
  debian:bookworm bash -lc '
    set -euo pipefail
    export DEBIAN_FRONTEND=noninteractive

    # tools for all stages
    apt-get update >/dev/null
    apt-get install -y --no-install-recommends \
      rsync e2fsprogs initramfs-tools zstd kmod xz-utils >/dev/null

    mkdir -p /mnt/src /mnt/dst

    # 1) mount images, copy base FS into target, add kernel bits + shim
    mount -o loop,ro /src/rootfs.img /mnt/src
    mount -o loop /work/build/kindle-rootfs.ext4 /mnt/dst

    rsync -aHAX --exclude boot /mnt/src/ /mnt/dst/
    if [ -e /mnt/src/boot ] && [ ! -e /mnt/dst/boot.original ]; then
      cp -a /mnt/src/boot /mnt/dst/boot.original
    fi
    mkdir -p /mnt/dst/boot
    mkdir -p /mnt/dst/dev/input
    if [ ! -c /mnt/dst/dev/input/event1 ]; then
      mknod /mnt/dst/dev/input/event1 c 13 65
      chmod 660 /mnt/dst/dev/input/event1
    fi
    rsync -aHAX /work/build/armmp/usr/lib/modules/6.12.48+deb13-armmp/ \
                 /mnt/dst/lib/modules/6.12.48+deb13-armmp/
    install -Dm755 /work/build/libfbshim.armhf.so \
                   /mnt/dst/usr/local/lib/libfbshim.armhf.so
    cp /work/build/armmp/boot/vmlinuz-6.12.48+deb13-armmp /mnt/dst/boot/
    cp /work/build/armmp/usr/lib/linux-image-6.12.48+deb13-armmp/vexpress-v2p-ca9.dtb /mnt/dst/boot/

    # 2) depmod inside the target root and uncompress kernel modules there
    depmod -b /mnt/dst 6.12.48+deb13-armmp
    find /mnt/dst/lib/modules/6.12.48+deb13-armmp -name "*.ko.xz" -exec unxz {} \;

    umount /mnt/src /mnt/dst

    # 3) build initramfs for ARM kernel from the toolchain tree
    mkdir -p /lib/modules/6.12.48+deb13-armmp /boot
    cp -a /work/build/armmp/usr/lib/modules/6.12.48+deb13-armmp/* \
          /lib/modules/6.12.48+deb13-armmp/
    cp /work/build/armmp/boot/config-6.12.48+deb13-armmp /boot/
    mkinitramfs -o /work/build/initrd.armhf.img 6.12.48+deb13-armmp
  '

###### TO RUN QEMU ######

QEMU_KINDLE_DIR=/Users/kian/code/qemu-kindle
sudo qemu-system-arm \
  -M vexpress-a9 -cpu cortex-a9 -m 512 \
  -kernel build/armmp/boot/vmlinuz-6.12.48+deb13-armmp \
  -initrd build/initrd.armhf.img \
  -dtb build/armmp/usr/lib/linux-image-6.12.48+deb13-armmp/vexpress-v2p-ca9.dtb \
  -drive if=none,id=hd0,file=build/kindle-rootfs.ext4,format=raw \
  -device virtio-blk-device,drive=hd0 \
  -append "root=/dev/vda rw rootfstype=ext4 console=ttyAMA0 init=/bin/bash" \
  -serial mon:stdio \
  -fsdev local,id=fs0,path="$PWD",security_model=none \
  -device virtio-9p-device,fsdev=fs0,mount_tag=hostshare \
  -chardev socket,id=fbch,path=/tmp/fbstream.sock,server=on,wait=off \
  -chardev socket,id=touchch,path=/tmp/touchstream.sock,server=on,wait=off \
  -device virtio-serial-device \
  -device virtserialport,chardev=fbch,name=org.kindle.fb \
  -device virtserialport,chardev=touchch,name=org.kindle.touch \
  -netdev vmnet-shared,id=net0 \
  -device virtio-net-device,netdev=net0 \
  -nographic



#### After running qemu, I haven't gotten init.d working yet, so it launches bash directly.
### Do the following inside the guest shell before trying anything ####

# in qemu:
# run this once inside the guest shell
find /lib/modules/6.12.48+deb13-armmp -name '*.ko.xz' -exec sh -c '
  for f; do
    xz -d "$f"
  done
' sh {} +

# rebuild module dependency lists now that they’re plain .ko files
depmod 6.12.48+deb13-armmp  # use the Kindle depmod if it works; otherwise reboot and run modprobe -C

# then load the pieces you need
modprobe virtio_blk
modprobe virtio_net
modprobe 9pnet_virtio
# Create the usual mounts Kindle init would have done
mount -t proc proc /proc
mount -t sysfs sys  /sys
# mount -t devtmpfs dev /dev 2>/dev/null || mount -t tmpfs dev /dev
mkdir -p /dev/pts /run
mount -t devpts devpts /dev/pts
# give yourself a RAM-backed place to write temp files
mount -t tmpfs tmpfs /run 2>/dev/null || true
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L,cache=mmap hostshare /mnt/host

# make /tmp resolve (symlink to /run is simplest)
ln -sfn /run /tmp

# re-run DHCP so udhcpc can now write resolv.conf, lease info, etc.
udhcpc -i eth0

# Optional, configure ln to symlink /mnt/host/fonts to /mnt/us/fonts
ln -sfn /mnt/host/fonts /mnt/us/fonts

# Alternative networking which might be relevant if vmnet-shared is unavailable
# # Bring up vexpress NIC manually (lan9118 appears as eth0)
# ip link set eth0 up
# ip addr add 10.0.2.15/24 dev eth0
# ip route add default via 10.0.2.2

# # DNS (SLiRP stub)
# echo 'nameserver 10.0.2.3' > /etc/resolv.conf

# Test host reachability
# ping -c1 192.168.2.1
# curl -v http://192.168.2.1:8123/ping



### Now to start the program with server.go running and connected to the fb and touch sockets
### the last argument is the binary you are trying to run, likely in a mirrors host dir at /mnt/host
cd /mnt/host; EMULATOR=1 LD_PRELOAD="/mnt/host/build/libfbshim.armhf.so:/mnt/host/build/libtouchshim.armhf.so" /mnt/host/build/show-decks 
