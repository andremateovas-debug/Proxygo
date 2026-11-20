use proxygo_engine::{inspect, InspectionRequest};
use serde::Serialize;
use std::env;
use std::io;
use std::os::unix::fs::{FileTypeExt, PermissionsExt};
use std::path::{Path, PathBuf};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWriteExt, BufReader, BufWriter};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;

const DEFAULT_SOCKET_PATH: &str = "/run/proxygo/engine.sock";
const DEVELOPMENT_SOCKET_PATH: &str = "/tmp/proxygo-engine.sock";
const MAX_LINE_BYTES: usize = 1024 * 1024;
const MAX_CONNECTIONS: usize = 128;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    run().await?;
    Ok(())
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let (listener, socket_path) = bind_configured_socket()?;
    let (shutdown_tx, shutdown_rx) = watch::channel(false);
    let semaphore = std::sync::Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut connections = JoinSet::new();

    let server_result = loop {
        tokio::select! {
            signal_result = tokio::signal::ctrl_c() => {
                if let Err(error) = signal_result {
                    break Err(error);
                }
                break Ok(());
            }
            _ = terminate.recv() => break Ok(()),
            accepted = listener.accept() => {
                match accepted {
                    Ok((stream, _)) => {
                        if let Ok(permit) = semaphore.clone().try_acquire_owned() {
                            let connection_shutdown = shutdown_rx.clone();
                            connections.spawn(async move {
                                let _permit = permit;
                                if let Err(error) = handle_connection(stream, connection_shutdown).await {
                                    eprintln!("proxygo engine: connection error: {error}");
                                }
                            });
                        } else {
                            eprintln!("proxygo engine: connection limit reached; rejecting client");
                        }
                    }
                    Err(error) => break Err(error),
                }
            }
        }
    };

    let _ = shutdown_tx.send(true);
    while let Some(result) = connections.join_next().await {
        if let Err(error) = result {
            eprintln!("proxygo engine: connection task failed: {error}");
        }
    }

    drop(listener);
    let cleanup_result = std::fs::remove_file(&socket_path);
    server_result?;
    match cleanup_result {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(Box::new(error)),
    }
}

fn bind_configured_socket() -> io::Result<(UnixListener, PathBuf)> {
    if let Some(path) = env::var_os("PROXYGO_SOCK_PATH") {
        let path = PathBuf::from(path);
        if path.as_os_str().is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PROXYGO_SOCK_PATH cannot be empty",
            ));
        }
        return bind_socket_at(&path).map(|listener| (listener, path));
    }

    let default_path = Path::new(DEFAULT_SOCKET_PATH);
    match bind_socket_at(default_path) {
        Ok(listener) => Ok((listener, default_path.to_path_buf())),
        Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
            let development_path = Path::new(DEVELOPMENT_SOCKET_PATH);
            let listener = bind_socket_at(development_path)?;
            Ok((listener, development_path.to_path_buf()))
        }
        Err(error) => Err(error),
    }
}

fn bind_socket_at(path: &Path) -> io::Result<UnixListener> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    remove_existing_socket(path)?;

    let listener = UnixListener::bind(path)?;
    if let Err(error) = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o660)) {
        drop(listener);
        let _ = std::fs::remove_file(path);
        return Err(error);
    }
    Ok(listener)
}

fn remove_existing_socket(path: &Path) -> io::Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to remove non-socket path {}", path.display()),
        )),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    }
}

async fn handle_connection(
    stream: UnixStream,
    mut shutdown: watch::Receiver<bool>,
) -> io::Result<()> {
    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = BufWriter::new(write_half);
    let mut line = Vec::new();

    loop {
        if *shutdown.borrow() {
            return Ok(());
        }

        let read_result = tokio::select! {
            result = read_bounded_line(&mut reader, &mut line) => result?,
            _ = shutdown.changed() => return Ok(()),
        };

        match read_result {
            LineRead::Eof => return Ok(()),
            LineRead::TooLong => {
                write_json_line(
                    &mut writer,
                    &mut shutdown,
                    &ErrorResponse {
                        error: "request_too_large",
                    },
                )
                .await?;
            }
            LineRead::Line => match serde_json::from_slice::<InspectionRequest>(&line) {
                Ok(request) => {
                    let response = inspect(&request);
                    write_json_line(&mut writer, &mut shutdown, &response).await?;
                }
                Err(_) => {
                    write_json_line(
                        &mut writer,
                        &mut shutdown,
                        &ErrorResponse {
                            error: "malformed_request",
                        },
                    )
                    .await?;
                }
            },
        }
    }
}

async fn read_bounded_line<R>(reader: &mut R, line: &mut Vec<u8>) -> io::Result<LineRead>
where
    R: AsyncBufRead + Unpin,
{
    line.clear();
    let mut seen_data = false;
    let mut too_long = false;

    loop {
        let (consumed, has_newline) = {
            let available = reader.fill_buf().await?;
            if available.is_empty() {
                return if !seen_data {
                    Ok(LineRead::Eof)
                } else if too_long {
                    Ok(LineRead::TooLong)
                } else {
                    Ok(LineRead::Line)
                };
            }

            let newline = available.iter().position(|byte| *byte == b'\n');
            let consumed = newline.map_or(available.len(), |index| index + 1);
            seen_data = true;

            if !too_long {
                if line.len().saturating_add(consumed) <= MAX_LINE_BYTES {
                    line.extend_from_slice(&available[..consumed]);
                } else {
                    too_long = true;
                    line.clear();
                }
            }
            (consumed, newline.is_some())
        };

        reader.consume(consumed);
        if has_newline {
            return Ok(if too_long {
                LineRead::TooLong
            } else {
                LineRead::Line
            });
        }
    }
}

async fn write_json_line<T: Serialize>(
    writer: &mut (impl AsyncWriteExt + Unpin),
    shutdown: &mut watch::Receiver<bool>,
    value: &T,
) -> io::Result<()> {
    let mut output = serde_json::to_vec(value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    output.push(b'\n');

    tokio::select! {
        result = async {
            writer.write_all(&output).await?;
            writer.flush().await
        } => result,
        _ = shutdown.changed() => Ok(()),
    }
}

#[derive(Serialize)]
struct ErrorResponse {
    error: &'static str,
}

enum LineRead {
    Eof,
    Line,
    TooLong,
}
