# Running Bhairav OS: VirtualBox, VMware, real machines

Build first (`.\bhairav.ps1 build`, or `make` in the toolchain), then:

```sh
make disk-image vm-images   # build/bhairavos.img (raw), .vdi (VirtualBox), .vmdk (VMware)
```

The disk image is a GPT disk with an EFI System Partition (ShoolLoader for
UEFI, Limine for BIOS) and a Bhairav data partition, where your files go.
It boots on its own; you don't need the ISO.

## VirtualBox

New VM: **Type** Other, **Version** Other/Unknown (64-bit).

| Setting | Use | Why |
|---|---|---|
| Memory | 512 MB or more | |
| Hard disk | "Use an existing virtual hard disk file": `build/bhairavos.vdi` | it holds the system and your files |
| Storage controller | IDE (the default), SATA (AHCI) or NVMe | all three have drivers |
| System → Enable EFI | either way | UEFI uses ShoolLoader (verified boot), BIOS uses Limine |
| System → Secure Boot | **off** (VirtualBox 7) | the loader is signed with your own key, not Microsoft's |
| System → Pointing device | **PS/2 Mouse** | there's no USB driver yet: the USB tablet won't move the pointer |
| Network → Adapter type | **Intel PRO/1000 MT Desktop** | PCnet and virtio-net have no driver |
| Display | VMSVGA or VBoxVGA | Bhairav draws on the firmware's framebuffer |

## VMware Workstation / Player / Fusion

New VM: "I will install the operating system later", **Guest OS** Other,
**Version** Other 64-bit.

| Setting | Use | Why |
|---|---|---|
| Hard disk | remove the new one; add an existing disk: `build/bhairavos.vmdk` | |
| Disk type | **SATA**, **NVMe** or **IDE** | not SCSI: there's no LSI Logic or PVSCSI driver |
| Firmware (Options → Advanced) | BIOS or UEFI; with UEFI, Secure Boot **off** | as above |
| Network adapter | e1000 (the default for "Other 64-bit") or e1000e | not vmxnet3 |
| Mouse/keyboard | the defaults (PS/2) | no USB driver yet |

Devices behind VMware's PCI bridges are found (the disk controller and
network card usually sit behind one).

## A real PC

Write `build/bhairavos.img` to a USB stick (all its contents are lost):
Rufus in **DD image** mode on Windows, or `dd if=build/bhairavos.img of=/dev/sdX bs=4M` on Linux.
Boot from it with the firmware's boot menu (often F12, F11, F9 or Esc).

- **Secure Boot:** turn it off, or enroll `build/secureboot.cer` in the
  firmware's db (keys are per build: see `docs/SECURITY.md` §13).
- **Your own disks are safe:** Bhairav uses a disk's FAT32 volume only if
  it's Bhairav's (label `BHAIRAV`, or a GPT partition of Bhairav's type).
  Anything else, Windows or Linux disks included, is left alone. Nothing
  is ever formatted.

What works on real hardware today, and what doesn't:

| Part | Works | Not yet |
|---|---|---|
| Boot | UEFI (ShoolLoader) and BIOS/CSM (Limine) | Secure Boot with Microsoft's keys (needs a shim) |
| CPU | any x86-64 with NX; one core is used | multicore |
| Screen | the firmware's framebuffer, any resolution | changing modes; GPU acceleration |
| Disk | AHCI (SATA), NVMe, IDE | **USB storage: after booting from a USB stick, its data partition isn't reachable**, so files need a Bhairav volume on an internal disk |
| Keyboard | PS/2, which is what most laptops' built-in keyboards are | **USB keyboards** (desktops) unless the firmware emulates PS/2 |
| Pointer | PS/2 mice and touchpads in PS/2 mode | **I2C touchpads** (most laptops since about 2016) and **USB mice** |
| Network | Intel e1000 family (82540-82547, 82574 e1000e), Realtek RTL8139 | Intel I219/I225, Realtek RTL8111/8125, **Wi-Fi** |
| ACPI | tables, AML (uACPI), power button, battery, temperature, embedded controller, shutdown, restart | sleep (S3) |
| IOMMU | Intel VT-d: DMA and interrupt remapping (the integrated GPU's own unit is left off; firmware's reserved DMA regions are kept) | AMD-Vi |

So on a typical laptop today, Bhairav boots to the desktop with the
built-in keyboard and the battery and temperature readings, but no
touchpad (use a PS/2 mouse if there's a port), no files (no Bhairav volume
on the internal disk) and no network (Wi-Fi). The order to fix that: a
USB (xHCI) driver with HID keyboards and mice and mass storage, then I2C
touchpads, then common Ethernet chips.

## What was tested, and how

There's no VirtualBox or VMware on the build machine, so their virtual
hardware is reproduced in QEMU:

| Setup | QEMU | Result |
|---|---|---|
| VirtualBox-like | i440FX/PIIX3 chipset, disk on IDE, e1000 82540EM, BIOS; the `.vdi` image | boots, files, network |
| VirtualBox-like (UEFI) | i440FX, disk on AHCI, OVMF | boots, files, network |
| VMware-like | devices behind PCIe root ports, e1000 82545EM, AHCI, 4 CPUs; the `.vmdk` on UEFI | boots, files, network |
| Laptop-like | NVMe disk, e1000e, 8 GiB, 4 CPUs, UEFI, with and without VT-d | boots, files, network |
| Someone else's disk | a FAT32 disk labelled OTHER | left alone, untouched |

Not tested: VirtualBox and VMware themselves, and real hardware.
