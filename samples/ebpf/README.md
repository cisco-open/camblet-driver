# eBPF XDP sample

This simple XDP program counts ethernet packages by protocol with the help of an eBPF map.

## Running in a Lima VM

Create the default Lima VM which is Ubuntu 22.04 currently:

```bash
limactl start
```

Make sure your directory containg this sample code is writeable in the Lima VM, I use home mount, it says it is dangerous, I don't care, you should!

```bash
> Open an editor to review or modify the current configuration
```

```yml
mounts:
- location: "~"
  # Configure the mountPoint inside the guest.
  # 🟢 Builtin default: value of location
  mountPoint: null
  # CAUTION: `writable` SHOULD be false for the home directory.
  # Setting `writable` to true is possible, but untested and dangerous.
  # 🟢 Builtin default: false
  writable: true
```

Enter the VM:

```bash
lima
```

Install the BPF related dependencies:

```bash
sudo apt install build-essential clang libbpf-dev linux-tools-generic
```

Build and run the example:

```bash
make
make createmap
make loadxdp

curl cisco.com
make logs
make dumpmap

make unloadxdp
```
