# qemu-kindle

Framebuffer and touch shims plus a host-side viewer to run Kindle ARM binaries
inside QEMU. The scripts here reproduce the environment used to debug Kindle
apps without touching the physical device.

This repository is meant to be followed step by step rather than by executing a
single setup script. The instructions below distill what `setup.sh` and the
`Makefile` do.

## Host requirements

- macOS with [Homebrew](https://brew.sh/) (other Unix hosts should work with
  equivalent packages)
- Docker (used to prepare the target root filesystem and initramfs)
- Go 1.24+
- An ARMv7 cross compiler that can target Kindle glibc (`arm-kindlehf-linux-gnueabihf-gcc`)
- QEMU with ARM support (`brew install qemu`)

You will also need:

- A Kindle `rootfs.img` extracted from an update. Copy it to
  `kindlos/rootfs.img`.
- The Debian ARMMP kernel package that the Kindle uses, e.g.\
  `linux-image-6.12.48+deb13-armmp_6.12.48-1_armhf.deb` downloaded from Debian.

## Repository layout

- `fbshim.c` / `touchshim.c` – LD_PRELOAD shims that intercept `/dev/fb0` and
  `/dev/input/event1` on the guest and shuttle data over virtio-serial sockets.
- `Makefile` – builds the shims (for macOS and ARMhf) and the Go viewer.
- `server.go` – host UI; displays framebuffer updates and forwards pointer input
  to the guest touch shim.
- `setup.sh` – documented sequence for assembling the Kindle rootfs, kernel, and
  initramfs inside Docker. Treat it as annotated notes rather than an executable
  script.

## 1. Build the shims

```sh
# Build ARMhf variants (requires arm-kindlehf-linux-gnueabihf-gcc)
make armhf

# Optionally build macOS .dylib for local testing
make mac
```

The ARM build drops `build/libfbshim.armhf.so` and `build/libtouchshim.armhf.so`
and copies convenience symlinks (`libfbshim.so`, `libtouchshim.so`) in the same
directory. These are what you will preload inside QEMU.

## 2. Build the Go viewer

```sh
go build -o server server.go
```

The `goserver` Makefile target does the same build and then runs the binary with
socket paths wired up:

```sh
make goserver  # builds ./server and launches it
```

Leave the viewer running before launching the Kindle application so it can
accept framebuffer/touch connections.

## 3. Prepare kernel assets

The setup expects `build/armmp` to contain the unpacked kernel Debian package.

```sh
mkdir -p build/armmp
dpkg-deb --extract /path/to/linux-image-6.12.48+deb13-armmp_6.12.48-1_armhf.deb build/armmp
```

If your workflow needs custom fonts or other host-mapped assets, create
subdirectories under `build/` (e.g. `build/fonts/`) before the next step.

## 4. Assemble the Kindle rootfs and initramfs

The Docker block in `setup.sh` rebuilds an ext4 image, layers in the Kindle
rootfs, stages the kernel modules, and generates an initrd. Adjust paths as
needed and run from the repository root:

```sh
export PATH_OF_KERNEL_DEB="/absolute/path/to/linux-image-6.12.48+deb13-armmp_6.12.48-1_armhf.deb"

rm -f build/kindle-rootfs.ext4
dd if=/dev/zero of=build/kindle-rootfs.ext4 bs=1M count=2048
mke2fs -t ext4 build/kindle-rootfs.ext4

docker run --rm --privileged --platform linux/arm/v7 \
  -v "$PWD":/work \
  -v "$PWD/kindlos/rootfs.img":/src/rootfs.img:ro \
  debian:bookworm bash -lc '
    set -euo pipefail

    apt-get update >/dev/null
    apt-get install -y --no-install-recommends \
      rsync e2fsprogs initramfs-tools zstd kmod xz-utils >/dev/null

    mkdir -p /mnt/src /mnt/dst
    mount -o loop,ro /src/rootfs.img /mnt/src
    mount -o loop /work/build/kindle-rootfs.ext4 /mnt/dst

    rsync -aHAX --exclude boot /mnt/src/ /mnt/dst/
    if [ -e /mnt/src/boot ]; then
      cp -a /mnt/src/boot /mnt/dst/boot.original
    fi
    mkdir -p /mnt/dst/boot /mnt/dst/dev/input
    [ -c /mnt/dst/dev/input/event1 ] || mknod /mnt/dst/dev/input/event1 c 13 65

    rsync -aHAX /work/build/armmp/usr/lib/modules/6.12.48+deb13-armmp/ \
                 /mnt/dst/lib/modules/6.12.48+deb13-armmp/
    install -Dm755 /work/build/libfbshim.armhf.so \
                   /mnt/dst/usr/local/lib/libfbshim.armhf.so
    cp /work/build/armmp/boot/vmlinuz-6.12.48+deb13-armmp /mnt/dst/boot/
    cp /work/build/armmp/usr/lib/linux-image-6.12.48+deb13-armmp/vexpress-v2p-ca9.dtb /mnt/dst/boot/

    depmod -b /mnt/dst 6.12.48+deb13-armmp
    find /mnt/dst/lib/modules/6.12.48+deb13-armmp -name "*.ko.xz" -exec unxz {} \;

    umount /mnt/src /mnt/dst

    mkdir -p /lib/modules/6.12.48+deb13-armmp /boot
    cp -a /work/build/armmp/usr/lib/modules/6.12.48+deb13-armmp/* \
          /lib/modules/6.12.48+deb13-armmp/
    cp /work/build/armmp/boot/config-6.12.48+deb13-armmp /boot/
    mkinitramfs -o /work/build/initrd.armhf.img 6.12.48+deb13-armmp
  '
```

On success you will have:

- `build/kindle-rootfs.ext4`
- `build/initrd.armhf.img`
- Updated kernel modules inside `build/armmp/usr/lib/modules/...`

Re-run this block any time you modify the shims or want a fresh rootfs image.

## 5. Boot QEMU

```sh
QEMU_KINDLE_DIR=$PWD
sudo qemu-system-arm \
  -M vexpress-a9 -cpu cortex-a9 -m 512 \
  -kernel "$QEMU_KINDLE_DIR/build/armmp/boot/vmlinuz-6.12.48+deb13-armmp" \
  -initrd "$QEMU_KINDLE_DIR/build/initrd.armhf.img" \
  -dtb "$QEMU_KINDLE_DIR/build/armmp/usr/lib/linux-image-6.12.48+deb13-armmp/vexpress-v2p-ca9.dtb" \
  -drive if=none,id=hd0,file="$QEMU_KINDLE_DIR/build/kindle-rootfs.ext4",format=raw \
  -device virtio-blk-device,drive=hd0 \
  -append "root=/dev/vda rw rootfstype=ext4 console=ttyAMA0 init=/bin/bash" \
  -serial mon:stdio \
  -fsdev local,id=fs0,path="$QEMU_KINDLE_DIR",security_model=none \
  -device virtio-9p-device,fsdev=fs0,mount_tag=hostshare \
  -chardev socket,id=fbch,path=/tmp/fbstream.sock,server=on,wait=off \
  -chardev socket,id=touchch,path=/tmp/touchstream.sock,server=on,wait=off \
  -device virtio-serial-device \
  -device virtserialport,chardev=fbch,name=org.kindle.fb \
  -device virtserialport,chardev=touchch,name=org.kindle.touch \
  -netdev vmnet-shared,id=net0 \
  -device virtio-net-device,netdev=net0 \
  -nographic
```

The guest boots into a root shell (`init=/bin/bash`) so you can finish setup
manually.

## 6. Guest-side preparation

Inside the guest shell run:

```sh
# Expand modules and rebuild dependency chains (only needed once per boot)
find /lib/modules/6.12.48+deb13-armmp -name '*.ko.xz' -exec xz -d {} +
depmod 6.12.48+deb13-armmp

# Load virtio devices and standard mounts
modprobe virtio_blk
modprobe virtio_net
modprobe 9pnet_virtio
mount -t proc proc /proc
mount -t sysfs sys /sys
mkdir -p /dev/pts /run
mount -t devpts devpts /dev/pts
mount -t tmpfs tmpfs /run || true
mkdir -p /mnt/host
mount -t 9p -o trans=virtio,version=9p2000.L,cache=mmap hostshare /mnt/host
ln -sfn /run /tmp

# Networking
udhcpc -i eth0
```

Optional: expose host fonts to the Kindle by `ln -sfn /mnt/host/fonts /mnt/us/fonts`.

## 7. Run Kindle binaries with the shims

On the host, keep the Go viewer running (`./server` or `make goserver`).

Inside the guest:

```sh
cd /mnt/host
EMULATOR=1 \
LD_PRELOAD="/mnt/host/build/libfbshim.armhf.so:/mnt/host/build/libtouchshim.armhf.so" \
./build/show-decks   # replace with your Kindle binary
```

The shims will stream framebuffer updates to `/tmp/fbstream.sock` and touch
events to `/tmp/touchstream.sock`, which the host viewer consumes.

## Troubleshooting

- `open /dev/input/event1: No such file or directory` – rerun the Docker setup;
  it now creates the expected character device inside the rootfs.
- Missing framebuffer updates – ensure the host viewer is listening on
  `/tmp/fbstream.sock` before launching the Kindle binary.
- Network access from the guest depends on QEMU’s `vmnet-shared`. If unavailable,
  use the SLiRP fallback commands in `setup.sh`.

## Cleaning up

```sh
make clean  # removes the build/ directory
```

Recreate the images afterwards by repeating steps 3–4.

