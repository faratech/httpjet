// Modified by FaraTech for httpjet; downstream changes are documented in vendor/PATCHES.md.

use std::{
    mem::size_of,
    os::fd::{AsRawFd, OwnedFd},
    sync::OnceLock,
};

use nix::errno::Errno;

struct Pipes {
    read_fd: OwnedFd,
    write_fd: OwnedFd,
}

static MEM_VALIDATE_PIPE: OnceLock<Pipes> = OnceLock::new();

#[inline]
#[cfg(any(target_os = "android", target_os = "linux"))]
fn create_pipe() -> nix::Result<(OwnedFd, OwnedFd)> {
    use nix::fcntl::OFlag;
    use nix::unistd::pipe2;

    pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
}

#[inline]
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
fn create_pipe() -> nix::Result<(OwnedFd, OwnedFd)> {
    use nix::fcntl::{FcntlArg, FdFlag, OFlag, fcntl};
    use nix::unistd::pipe;
    fn set_flags(fd: &impl std::os::fd::AsFd) -> nix::Result<()> {
        let mut flags = FdFlag::from_bits(fcntl(fd, FcntlArg::F_GETFD)?).unwrap();
        flags |= FdFlag::FD_CLOEXEC;
        fcntl(fd, FcntlArg::F_SETFD(flags))?;
        let mut flags = OFlag::from_bits(fcntl(fd, FcntlArg::F_GETFL)?).unwrap();
        flags |= OFlag::O_NONBLOCK;
        fcntl(fd, FcntlArg::F_SETFL(flags))?;
        Ok(())
    }

    let (read_fd, write_fd) = pipe()?;
    set_flags(&read_fd)?;
    set_flags(&write_fd)?;
    Ok((read_fd, write_fd))
}

#[inline]
fn read_raw(fd: i32, buf: &mut [u8]) -> nix::Result<usize> {
    // `buf` is valid for writes of `buf.len()` bytes for the duration of this call.
    let result = unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) };
    if result < 0 {
        Err(Errno::last())
    } else {
        Ok(result as usize)
    }
}

#[inline]
fn write_addr_raw(fd: i32, addr: *const libc::c_void, len: usize) -> nix::Result<usize> {
    // SAFETY: write(2) asks the kernel to copy from userspace and reports an unreadable address as
    // an error. Passing the untrusted pointer directly is intentional and avoids creating a Rust
    // reference or slice before the address has been validated.
    let result = unsafe { libc::write(fd, addr, len) };
    if result < 0 {
        Err(Errno::last())
    } else {
        Ok(result as usize)
    }
}

pub(crate) fn initialize() -> nix::Result<()> {
    if MEM_VALIDATE_PIPE.get().is_some() {
        return Ok(());
    }
    let (read_fd, write_fd) = create_pipe()?;
    let _ = MEM_VALIDATE_PIPE.set(Pipes { read_fd, write_fd });
    Ok(())
}

fn validation_pipe() -> Option<&'static Pipes> {
    if MEM_VALIDATE_PIPE.get().is_none() && initialize().is_err() {
        return None;
    }
    MEM_VALIDATE_PIPE.get()
}

// validate whether the address `addr` is readable through `write()` to a pipe
//
// if the second argument of `write(ptr, buf)` is not a valid address, the
// `write()` will return an error the error number should be `EFAULT` in most
// cases, but we regard all errors (except EINTR) as a failure of validation
pub fn validate(addr: *const libc::c_void) -> bool {
    if addr.is_null() {
        return false;
    }
    let Some(pipe) = validation_pipe() else {
        return false;
    };

    const CHECK_LENGTH: usize = 2 * size_of::<*const libc::c_void>() / size_of::<u8>();

    // read data in the pipe
    let read_fd = pipe.read_fd.as_raw_fd();
    let valid_read = loop {
        let mut buf = [0u8; CHECK_LENGTH];

        match read_raw(read_fd, &mut buf) {
            Ok(bytes) => break bytes > 0,
            Err(_err @ Errno::EINTR) => continue,
            Err(_err @ Errno::EAGAIN) => break true,
            Err(_) => break false,
        }
    };

    if !valid_read {
        return false;
    }

    let write_fd = pipe.write_fd.as_raw_fd();
    loop {
        match write_addr_raw(write_fd, addr, CHECK_LENGTH) {
            Ok(bytes) => break bytes > 0,
            Err(_err @ Errno::EINTR) => continue,
            Err(_) => break false,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn validate_stack() {
        let i = 0;

        assert!(validate(&i as *const _ as *const libc::c_void));
    }

    #[test]
    fn validate_heap() {
        let vec = vec![0; 1000];

        for i in vec.iter() {
            assert!(validate(i as *const _ as *const libc::c_void));
        }
    }

    #[test]
    fn failed_validate() {
        assert!(!validate(std::ptr::null::<libc::c_void>()));
        assert!(!validate(-1_i32 as usize as *const libc::c_void))
    }

    #[test]
    fn validation_pipe_is_a_process_lifetime_singleton() {
        initialize().unwrap();
        let before = validation_pipe().unwrap();
        let before_fds = (before.read_fd.as_raw_fd(), before.write_fd.as_raw_fd());

        std::thread::scope(|scope| {
            for _ in 0..16 {
                scope.spawn(|| {
                    initialize().unwrap();
                    let value = 1u64;
                    assert!(validate(&value as *const _ as *const libc::c_void));
                });
            }
        });

        let after = validation_pipe().unwrap();
        assert_eq!(
            before_fds,
            (after.read_fd.as_raw_fd(), after.write_fd.as_raw_fd())
        );
    }
}
