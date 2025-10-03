use crate::error::{Error, Result};
use socket2::Socket;

#[cfg(any(target_os = "linux", target_os = "android"))]
use std::ffi::CString;
#[cfg(any(target_os = "linux", target_os = "android"))]
use std::os::fd::AsRawFd;

/// Configure `SO_BINDTODEVICE` for a socket when an interface is provided.
///
/// On Linux/Android this uses `setsockopt` to constrain the socket to the
/// supplied interface. Other platforms return an error indicating that the
/// behaviour is unsupported so callers can surface a clear configuration issue.
pub fn bind_to_device(socket: &Socket, interface: &str) -> Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let c_iface = CString::new(interface.as_bytes()).map_err(|_| {
            Error::Media(format!(
                "interface name contains interior NUL bytes: {interface}"
            ))
        })?;
        // Safety: we pass a valid pointer and length from the CString that
        // remains alive for the duration of the call.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                c_iface.as_ptr() as *const libc::c_void,
                c_iface.as_bytes_with_nul().len() as libc::socklen_t,
            )
        };
        if result != 0 {
            let io_err = std::io::Error::last_os_error();
            return Err(Error::Media(format!(
                "failed to bind socket to interface {interface}: {io_err}"
            )));
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "linux", target_os = "android")))]
    {
        Err(Error::Media(format!(
            "interface binding not supported on this platform ({interface})"
        )))
    }
}
