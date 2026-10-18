//! A separate owner-only host listener. It has no TLS/credential signing API
//! and is never selected by the untrusted guest protocol.
use crate::{custody::approval::Shared, files, json, tls, Error, Outcome};
use serde_json::json;
use std::{
    fs,
    io::Write,
    os::unix::{
        fs::{MetadataExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc, Mutex,
    },
    time::Duration,
};

#[derive(Clone)]
pub struct Control {
    pub(crate) path: PathBuf,
    pub(crate) state: Arc<Shared>,
}
pub struct Running {
    control: Control,
    stopped: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
    device: u64,
    inode: u64,
}
impl Control {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
    pub fn listen(self) -> Outcome<Running> {
        use std::os::unix::ffi::OsStrExt;
        if !self.path.is_absolute() || self.path.as_os_str().as_bytes().len() > 100 {
            return Err(Error::UnsafeFile);
        }
        files::private_directory(self.path.parent().ok_or(Error::UnsafeFile)?)?;
        let listener = UnixListener::bind(&self.path).map_err(|_| Error::UnsafeFile)?;
        let info = fs::symlink_metadata(&self.path).map_err(|_| Error::UnsafeFile)?;
        let stopped = Arc::new(AtomicBool::new(false));
        let mut running = Running {
            control: self,
            stopped: stopped.clone(),
            worker: None,
            device: info.dev(),
            inode: info.ino(),
        };
        fs::set_permissions(&running.control.path, fs::Permissions::from_mode(0o600))
            .map_err(|_| Error::UnsafeFile)?;
        listener
            .set_nonblocking(true)
            .map_err(|_| Error::InternalError)?;
        let state = running.control.state.clone();
        running.worker = Some(
            std::thread::Builder::new()
                .name("broker-control".into())
                .spawn(move || {
                    let (send, recv) = mpsc::sync_channel::<UnixStream>(16);
                    let recv = Arc::new(Mutex::new(recv));
                    let mut workers = Vec::new();
                    for _ in 0..4 {
                        let recv = recv.clone();
                        let job_state = state.clone();
                        let Ok(worker) = std::thread::Builder::new()
                            .name("broker-operator".into())
                            .spawn(move || loop {
                                let socket = match recv.lock() {
                                    Ok(r) => r.recv(),
                                    Err(_) => return,
                                };
                                let Ok(socket) = socket else { return };
                                let _ = serve(socket, &job_state);
                            })
                        else {
                            state.revoke();
                            return;
                        };
                        workers.push(worker);
                    }
                    while !stopped.load(Ordering::Acquire) {
                        match listener.accept() {
                            Ok((socket, _)) => {
                                let _ = send.try_send(socket);
                            }
                            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                                std::thread::sleep(Duration::from_millis(20))
                            }
                            Err(_) => {
                                state.revoke();
                                break;
                            }
                        }
                    }
                    drop(send);
                    for worker in workers {
                        let _ = worker.join();
                    }
                })
                .map_err(|_| Error::InternalError)?,
        );
        Ok(running)
    }
}
fn serve(mut socket: UnixStream, state: &Shared) -> Outcome<()> {
    let peer = rustix::net::sockopt::socket_peercred(&socket).map_err(|_| Error::Denied)?;
    if peer.uid != rustix::process::geteuid() {
        return Err(Error::Denied);
    }
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Error::InternalError)?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|_| Error::InternalError)?;
    let killer = socket.try_clone().map_err(|_| Error::InternalError)?;
    let _deadline = tls::Deadline::start_for(Duration::from_secs(5), move || {
        let _ = killer.shutdown(std::net::Shutdown::Both);
    });
    let result = tls::frame(&mut socket, 65536)
        .and_then(|raw| json::parse(&raw, 65536).map_err(|_| Error::InvalidRequest))
        .and_then(|value| state.execute(&value));
    let reply = result
        .unwrap_or_else(|error| json!({"version":1,"ok":false,"error":{"code":error.code()}}));
    let data = json::canonical(&reply);
    if data.len() > 1048576 {
        return Err(Error::Exhausted);
    }
    socket
        .write_all(&data)
        .and_then(|_| socket.write_all(b"\n"))
        .map_err(|_| Error::InternalError)
}
impl Drop for Running {
    fn drop(&mut self) {
        self.control.state.revoke();
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        if let Ok(info) = fs::symlink_metadata(&self.control.path) {
            if info.dev() == self.device && info.ino() == self.inode {
                let _ = fs::remove_file(&self.control.path);
            }
        }
    }
}
