package ivshmem

import (
	"os"
	"syscall"
	"io/ioutil"

	"golang.org/x/sys/unix"
)

func Load_module(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// first try finit_module(2), then init_module(2)
	err = unix.FinitModule(int(f.Fd()), "", 0)
	if err != nil {
		if err.Error() == unix.ENOSYS.Error() {
			buf, err := ioutil.ReadAll(f)
			if err != nil {
				return err
			}
			return unix.InitModule(buf, "")
		}
	}
	return err
}

func GetSharedMappingGuest(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	// The offset is necessary to map the right mapping of the uio device (map1).
	shmem, err := syscall.Mmap(int(f.Fd()), 4096 * 1, 512 << 20, syscall.PROT_READ | syscall.PROT_WRITE, syscall.MAP_SHARED);
	if err != nil {
		return nil, err
	}
	return shmem, nil
}

func GetSharedMappingHost(path string) ([]byte, error) {
	f, err := os.OpenFile(path, os.O_RDWR, 0644)
	if err != nil {
		return nil, err
	}
	// The offset is necessary to map the right mapping of the uio device (map1).
	shmem, err := syscall.Mmap(int(f.Fd()), 0, 512 << 20, syscall.PROT_READ | syscall.PROT_WRITE, syscall.MAP_SHARED);
	if err != nil {
		return nil, err
	}
	return shmem, nil
}

func UnmapHostIvshmem(mapping []byte) error {
	return syscall.Munmap(mapping)
}
