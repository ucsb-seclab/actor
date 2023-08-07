# ACTOR: Action-Guided Kernel Fuzzing

ACTOR, our action-guided kernel fuzzing framework, deviates from traditional methods.
Instead of focusing on code coverage optimization, our approach generates fuzzer programs (inputs) that leverage our understanding of triggered actions and their temporal relationships.
Specifically, we first capture actions that potentially operate on shared data structures at different times.
Then, we synthesize programs using those actions as building blocks, guided by bug templates expressed in our domain-specific language.

For more details, please refer to our [paper](https://www.usenix.org/conference/usenixsecurity23/presentation/fleischer).
This repo contains all necessary sources and instructions to setup and run ACTOR.

## Setup

Follow the steps below to get ACTOR up and running!

0. Check out this repo.
```
git clone https://github.com/ucsb-seclab/actor.git
cd actor
```

### Dependencies

You will need to build a Linux kernel, syzkaller.
Make sure you have all build dependencies for these tools installed (check their official websites).


### Static Analysis

1. Check out the target kernel you want to fuzz (we provide the instrumentation for v5.17 and v6.2-rc5), e.g. for v6.2-rc5
```
git clone https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git
cd linux
git checkout 2241ab53cbb5cdb08a6b2d4688feb13971058f65
```

2. [Optional] If it is not one of the kernel versions with provided instrumentation, adapt the instrumentation to work with the target kernel version. For this, check out the patch file. Versions close to the supported ones should be very easy to instrument.

3. Apply the changes for the instrumentation.
```
git apply ../setup/kernel/v6-2-rc5.patch
cd ..
```

4. Install clang 14 or newer. You can either build LLVM from source or download prebuilt libraries. Please refer to LLVM's documentation for detailed steps. Make sure to add clang to your PATH.

5. Next, compile the static analysis pass:
```
cd semantic-inference
mkdir build
cd build
cmake ..
make
cd ../..
```

6. `semantic-inference/my-clang` is a wrapper script for invoking the LLVM pass. Change the path of clang in this script to wherever clang and the LLVM pass are located on your system (e.g., find that location with `which clang` if clang is in your PATH).

Now we are ready to perform the static analysis! 
```
cd linux
```

7. But first, you need a kernel config. We suggest to either use defconfig or syzbots, but any config that works for you is fine. You can generate defconfig by `make defconfig`.

8. Apply changes required by ACTOR to the chosen kernel config:
```
./scripts/kconfig/merge_config.sh .config ../setup/kernel/actor_static.config
```

9. Build the kernel/perform the static analysis. If you don't want to use all cores, replace `$(nproc)` with the number of cores you want to use. The `ptrs.txt` file will later be used by ACTOR for the semantic refinement.
```
make CC=../semantic-inference/my-clang -j$(nproc) 2>ptrs.txt
```


### Kernel preparation

1. Clean up the kernel repo. This will delete the kernel config, please save it beforehand if it is a custom config.
```
make clean
make mrproper
```

2. Regenerate the config/restore the config. Apply changes required by ACTOR:
```
./scripts/kconfig/merge_config.sh .config ../setup/kernel/actor.config
```

3. Build the kernel for fuzzing. If you don't want to use all cores, replace `$(nproc)` with the number of cores you want to use.
```
make -j$(nproc)
cd ..
```


### Fuzzer setup

1. Make sure go is in your `PATH` and `GOPATH` points to `.`, the root of this repo.

2. Build ACTOR.
```
cd src/github.com/google/syzkaller/
go mod tidy
go mod vendor
export GO111MODULE=off
make -j$(nproc)
cd ../../../../
```

### VM setup

1. Build an image for the VM. Please follow syzkaller's instructions [here](https://github.com/google/syzkaller/blob/master/docs/linux/setup_ubuntu-host_qemu-vm_x86-64-kernel.md#image). ACTOR expects the image and the corresponding key under `./image`. 

2. Build IVSHMEM.
```
cd setup/ivshmem/kernel_module/uio
make
```

3. ACTOR expects the kernel modules `uio.ko` and `uio_ivshmem.ko` in the directory `/root` in the VM. Start QEMU with the image, e.g.,
```
qemu-system-x86_64 -kernel linux/arch/x86/boot/bzImage -append "console=ttyS0 root=/dev/sda debug earlyprintk=serial slub_debug=QUZ nokaslr" -hda image/bullseye.img -net user,hostfwd=tcp::10021-:22 -net nic -enable-kvm -nographic -m 4G -smp 2
```

4. In a separate terminal, transfer the two required files via scp. Once you are done, you can shutdown the VM.
```
scp -i image/bullseye.id_rsa -P10021 linux/drivers/uio/uio.ko root@localhost:
scp -i image/bullseye.id_rsa -P10021 setup/ivshmem/kernel_module/uio/uio_ivshmem.ko root@localhost:
```


## Running ACTOR

1. Create an work directory.
```
mkdir -p out/workdir
```

2. Copy the `ptrs.txt` file into the work directory.
```
cp linux/ptrs.txt out/workdir/
```

3. Start fuzzing.
```
cd setup/actor
../../src/github.com/google/syzkaller/bin/syz-manager -config actor.config
```


## Porting ACTOR to a different kernel

Most of the changes are in a few standalone files that can be copied between versions.
As long as the kernel API used in those files does not change, there should not be anything to be done in them.
The main task is to adapt the changes in existing files.
For this, you can take any of the two diffs provided as a guideline.
In many cases, especially if the kernel version is close to the one of the diff, the changes are minimal.

Please note: the implemenation of the kernel module and the fuzzer refer to **actions** as **events**.

## Bug reports

* [KASAN: use-after-free Read in drm_gem_object_release](https://groups.google.com/u/1/g/syzkaller/c/QGWgJCJglJg)
* [general protection fault in sock_def_error_report](https://groups.google.com/u/1/g/syzkaller/c/8Vmn38baZts)
* [BUG: unable to handle kernel paging request in imageblit](https://groups.google.com/u/1/g/syzkaller/c/hSAMlMQpY5g)
* [KASAN: vmalloc-out-of-bounds Write in snd_pcm_hw_params](https://groups.google.com/u/1/g/syzkaller/c/C4oOHZe1RMs)
* [KASAN: use-after-free Read in post_one_notification](https://groups.google.com/u/1/g/syzkaller/c/DHbFczxkGSc)
* [INFO: task hung in gfs2_read_super](https://groups.google.com/u/1/g/syzkaller/c/DuAVCp0w4lQ)
* [general protection fault in start_motor](https://groups.google.com/u/1/g/syzkaller/c/dWYyDaDQa0M)
* [KASAN: slab-out-of-bounds Read in ntfs_get_ea](https://groups.google.com/u/1/g/syzkaller/c/Rlcdh-IkNek)
* [KASAN: vmalloc-out-of-bounds Read in cleanup_bitmap_list](https://groups.google.com/u/1/g/syzkaller/c/GfGWF9Bg5aQ)
* [KASAN: use-after-free Read in run_unpack](https://groups.google.com/u/1/g/syzkaller/c/kmeEytUP9Dk)
* [KASAN: use-after-free Read in __io_remove_buffers](https://groups.google.com/u/1/g/syzkaller/c/FG7C4_Rzbdk)
* [KASAN: invalid-free in __io_uring_register](https://groups.google.com/u/1/g/syzkaller/c/OubBSjNf3W4)
* [KASAN: use-after-free Read in reiserfs_fill_super](https://groups.google.com/u/1/g/syzkaller/c/PYwxEAZOttM)
* [INFO: task hung in __bread_gfp](https://groups.google.com/u/1/g/syzkaller/c/Db7yGdTSe9s)
* [WARNING in inet_sock_destruct](https://groups.google.com/u/1/g/syzkaller/c/gXTYyztJYWg)
* [kernel BUG in f2fs_new_node_page](https://groups.google.com/u/1/g/syzkaller/c/G52HcBagKg8)
* [kernel BUG in ntfs_read_folio](https://groups.google.com/u/1/g/syzkaller/c/mKE24U8MFXk)
* [INFO: task hung in __floppy_read_block_0](https://groups.google.com/u/1/g/syzkaller/c/oQ8oR9-ItAI)
* [KMSAN: uninit-value in __dma_map_sg_attrs](https://groups.google.com/u/1/g/syzkaller/c/hOTcWjt0TdI)
* [KMSAN: uninit-value in sr_check_events](https://groups.google.com/u/1/g/syzkaller/c/BOu5iBRVNgA)
* [KMSAN: uninit-value in post_read_mst_fixup](https://groups.google.com/u/1/g/syzkaller/c/Nuzcbq-CCXk)
* [KMSAN: uninit-value in nilfs_add_checksums_on_logs](https://groups.google.com/u/1/g/syzkaller/c/FnmR_s3h2Qk)
* [KMSAN: uninit-value in generic_bin_search](https://groups.google.com/u/1/g/syzkaller/c/c6eaf5vbswo)
* [BUG: unable to handle kernel NULL pointer dereference in ntfs_iget5](https://groups.google.com/u/1/g/syzkaller/c/eZyxATf8MMQ)

## Citing ACTOR

If you find this work useful for your research, we would appreciate citations using this Bibtex entry.

```
@inproceedings{Fleischer23,
   author = {Marius Fleischer and Dipanjan Das and Priyanka Bose and Weiheng Bai and Kangjie Lu and Mathias Payer and Christopher Kruegel and Giovanni Vigna},
   title = {{ACTOR}: Action-Guided Kernel Fuzzing},
   booktitle = {32th {USENIX} Security Symposium ({USENIX} Security 23)},
   year = {2023},
   address = {Anaheim, CA},
   url = {https://www.usenix.org/conference/usenixsecurity23/presentation/fleischer},
   publisher = {{USENIX} Association},
}
```
