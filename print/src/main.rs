use std::{
    collections::BTreeSet,
    env,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{anyhow, bail, Context};
use clap::{Parser, Subcommand};
use defmt_decoder::{
    log::{
        format::{Formatter, FormatterConfig, HostFormatter},
        DefmtLoggerType,
    },
    DecodeError, Frame, Locations, StreamDecoder, Table, DEFMT_VERSIONS,
};
use goblin::elf::Elf;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::{
    fs,
    io::{self, AsyncReadExt, AsyncWriteExt, Stdin},
    net::TcpStream,
    select,
    sync::mpsc::Receiver,
};
use tokio_serial::{SerialPort, SerialPortBuilderExt, SerialStream};

/// Prints defmt-encoded logs to stdout
#[derive(Parser, Clone)]
#[command(name = "defmt-print")]
struct Opts {
    /// The firmware running on the device being logged.
    ///
    /// May be repeated for devices that log several images over one stream (e.g. bootloader and
    /// application). The images must use the same defmt encoding and their defmt indices must not
    /// overlap. With `tcp --set-addr`, they must also place the RTT control block (`_SEGGER_RTT`)
    /// at the same address.
    #[arg(short, required = true, conflicts_with("version"))]
    elf: Vec<PathBuf>,

    /// Emit logs in JSON format
    #[arg(long)]
    json: bool,

    /// A format string for target-generated logs
    #[arg(long)]
    log_format: Option<String>,

    /// A format string for host-generated logs
    #[arg(long)]
    host_log_format: Option<String>,

    /// Log any malformed defmt frames that are being skipped
    #[arg(long)]
    show_skipped_frames: bool,

    /// Print extra detail
    #[arg(short, long)]
    verbose: bool,

    /// Print the version number, and quit
    #[arg(short = 'V', long)]
    version: bool,

    /// Reload the ELF file when it changes
    #[arg(short, long)]
    watch_elf: bool,

    /// Which operation to perform
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand, Clone)]
enum Command {
    /// Read defmt frames from stdin (default)
    Stdin,
    /// Read defmt frames from a TCP server
    Tcp {
        /// Which host to connect to
        #[arg(long, env = "RTT_HOST", default_value = "localhost")]
        host: String,

        /// Which port to connect to (uses the J-Link port by default)
        #[arg(long, env = "RTT_PORT", default_value_t = 19021)]
        port: u16,

        /// Tell Segger J-Link what the RTT address is
        #[arg(long)]
        set_addr: bool,
    },
    /// Read defmt frames from a serial port
    Serial {
        #[arg(long, env = "SERIAL_PORT", default_value = "/dev/ttyUSB0")]
        path: PathBuf,

        #[arg(long, env = "SERIAL_BAUD", default_value_t = 115200)]
        baud: u32,

        #[arg(long, env = "SERIAL_DTR", default_value_t = false)]
        dtr: bool,
    },
}

enum Source {
    Stdin(Stdin),
    Tcp(TcpStream, bool),
    Serial(SerialStream),
}

impl Source {
    fn stdin() -> Self {
        Source::Stdin(io::stdin())
    }

    async fn tcp(host: String, port: u16, set_addr: bool) -> anyhow::Result<Self> {
        match TcpStream::connect((host, port)).await {
            Ok(stream) => Ok(Source::Tcp(stream, set_addr)),
            Err(e) => Err(anyhow!(e)),
        }
    }

    fn serial(path: PathBuf, baud: u32, dtr: bool) -> anyhow::Result<Self> {
        let mut ser = tokio_serial::new(path.to_string_lossy(), baud).open_native_async()?;
        ser.set_timeout(Duration::from_millis(500))?;
        if dtr {
            ser.write_data_terminal_ready(true)?;
        }
        Ok(Source::Serial(ser))
    }

    /// Whether this source tells the probe where the RTT control block is.
    fn sets_rtt_addr(&self) -> bool {
        matches!(self, Source::Tcp(_, true))
    }

    async fn set_rtt_addr(&mut self, elf_bytes: &[u8]) -> anyhow::Result<()> {
        let Source::Tcp(tcpstream, set_addr) = self else {
            return Ok(());
        };

        // if they don't want to set the addr, do nothing
        if !*set_addr {
            return Ok(());
        }

        let addr = segger_rtt_addr(elf_bytes)?;

        let cmd = format!("$$SEGGER_TELNET_ConfigStr=SetRTTAddr;{addr:#x}$$");
        tcpstream.write_all(cmd.as_bytes()).await?;

        Ok(())
    }

    async fn read(&mut self, buf: &mut [u8]) -> anyhow::Result<(usize, bool)> {
        match self {
            Source::Stdin(stdin) => {
                let n = stdin.read(buf).await?;
                Ok((n, n == 0))
            }
            Source::Tcp(tcpstream, ..) => {
                let n = tcpstream.read(buf).await?;
                Ok((n, n == 0))
            }
            Source::Serial(serial) => {
                let n = serial.read(buf).await?;
                Ok((n, n == 0))
            }
        }
    }
}

const READ_BUFFER_SIZE: usize = 1024;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let opts = Opts::parse();

    if opts.version {
        return print_version();
    }

    // We create the source outside of the run command since recreating the stdin looses us some frames
    let mut source = match opts.command.clone() {
        None | Some(Command::Stdin) => Source::stdin(),
        Some(Command::Tcp {
            host,
            port,
            set_addr,
        }) => Source::tcp(host, port, set_addr).await?,
        Some(Command::Serial { path, baud, dtr }) => Source::serial(path, baud, dtr)?,
    };

    if opts.watch_elf {
        run_and_watch(opts, &mut source).await
    } else {
        run(opts, &mut source).await
    }
}

async fn has_file_changed(
    rx: &mut Receiver<Result<Event, notify::Error>>,
    paths: &[PathBuf],
) -> bool {
    loop {
        if let Some(Ok(event)) = rx.recv().await {
            if event.paths.iter().any(|changed| paths.contains(changed)) {
                if let notify::EventKind::Create(_) | notify::EventKind::Modify(_) = event.kind {
                    break;
                }
            }
        }
    }
    true
}

async fn run_and_watch(opts: Opts, source: &mut Source) -> anyhow::Result<()> {
    let (tx, mut rx) = tokio::sync::mpsc::channel(1);

    let paths = opts
        .elf
        .iter()
        .map(|elf| elf.canonicalize())
        .collect::<Result<Vec<_>, _>>()?;

    let mut watcher = RecommendedWatcher::new(
        move |res| {
            let _ = tx.blocking_send(res);
        },
        Config::default(),
    )?;
    // We want the elf directory instead of the elf, since some editors remove
    // and recreate the file on save which will remove the notifier
    let directory_paths: BTreeSet<&Path> = paths
        .iter()
        .map(|path| {
            path.parent()
                .ok_or_else(|| anyhow!("{} has no parent directory", path.display()))
        })
        .collect::<Result<_, _>>()?;
    for directory_path in directory_paths {
        watcher.watch(directory_path, RecursiveMode::NonRecursive)?;
    }

    loop {
        select! {
            r = run(opts.clone(), source) => return r,
            _ = has_file_changed(&mut rx, &paths) => ()
        }
    }
}

async fn run(opts: Opts, source: &mut Source) -> anyhow::Result<()> {
    let Opts {
        elf,
        json,
        log_format,
        host_log_format,
        show_skipped_frames,
        verbose,
        ..
    } = opts;

    // reject duplicate ELFs (e.g. `fw.elf` and `./fw.elf`); identical files would fail the
    // compatibility check with a confusing index-overlap message
    let mut seen = BTreeSet::new();
    for path in &elf {
        if let Ok(canonical) = path.canonicalize() {
            if !seen.insert(canonical) {
                bail!("ELF {} was given more than once", path.display());
            }
        }
    }

    let mut elfs = Vec::with_capacity(elf.len());
    for path in elf {
        elfs.push(LoadedElf::load(path).await?);
    }
    check_elfs_compatible(&elfs, source.sets_rtt_addr())?;

    // Give the _SEGGER_RTT address to the source.
    source.set_rtt_addr(&elfs[0].bytes).await?;

    let logger_type = if json {
        DefmtLoggerType::Json
    } else {
        DefmtLoggerType::Stdout
    };

    let cloned_format = log_format.clone().unwrap_or_default();
    let mut formatter_config = if log_format.is_some() {
        FormatterConfig::custom(cloned_format.as_str())
    } else if verbose {
        FormatterConfig::default().with_location()
    } else {
        FormatterConfig::default()
    };

    formatter_config.is_timestamp_available = elfs.iter().any(|elf| elf.table.has_timestamp());

    let cloned_host_format = host_log_format.clone().unwrap_or_default();
    let host_formatter_config = if host_log_format.is_some() {
        FormatterConfig::custom(cloned_host_format.as_str())
    } else if verbose {
        FormatterConfig::default().with_location()
    } else {
        FormatterConfig::default()
    };

    let formatter = Formatter::new(formatter_config);
    let host_formatter = HostFormatter::new(host_formatter_config);

    defmt_decoder::log::init_logger(formatter, host_formatter, logger_type, move |metadata| {
        match verbose {
            false => defmt_decoder::log::is_defmt_frame(metadata), // We display *all* defmt frames, but nothing else.
            true => true,                                          // We display *all* frames.
        }
    });

    let mut buf = [0; READ_BUFFER_SIZE];
    let mut stream_decoders: Vec<_> = elfs
        .iter()
        .map(|elf| elf.table.new_stream_decoder())
        .collect();
    // We have already enforced that all elfs have the same format
    let can_recover = elfs[0].table.encoding().can_recover();
    let current_dir = env::current_dir()?;

    loop {
        // read from stdin or tcpstream and push it to the decoders
        let (n, eof) = source.read(&mut buf).await?;

        // if 0 bytes where read, we reached EOF, so quit
        if eof {
            break Ok(());
        }

        for stream_decoder in &mut stream_decoders {
            stream_decoder.received(&buf[..n]);
        }

        // Every decoder sees the same bytes and so the same frame boundaries. Step them together:
        // the decoder whose table owns the frame's index decodes it and the others reject it.
        loop {
            match step_decoders(&mut stream_decoders, &elfs)? {
                Step::NeedMoreData => break,
                Step::Decoded(frame, locs) => {
                    forward_to_logger(&frame, location_info(locs, &frame, &current_dir))
                }
                Step::Malformed => {
                    // if recovery is impossible, abort
                    if !can_recover {
                        return Err(DecodeError::Malformed.into());
                    }
                    // if recovery is possible, skip the current frame and continue with new data
                    // bug: https://github.com/rust-lang/rust-clippy/issues/9810
                    #[allow(clippy::print_literal)]
                    if show_skipped_frames || verbose {
                        println!("(HOST) malformed frame skipped");
                        println!("└─ {} @ {}:{}", env!("CARGO_PKG_NAME"), file!(), line!());
                    }
                }
            }
        }
    }
}

/// One frame-boundary step across all decoders.
enum Step<'a> {
    /// No decoder has a complete frame yet; the stream needs more bytes.
    NeedMoreData,
    /// One decoder's table owns the frame; the others rejected it.
    Decoded(Frame<'a>, &'a Option<Locations>),
    /// Every decoder rejected the frame.
    Malformed,
}

/// Every decoder sees the same bytes and so the same frame boundaries. Step them together: the
/// decoder whose table owns a frame's index decodes it, the others reject it.
fn step_decoders<'a, 't>(
    stream_decoders: &'a mut [Box<dyn StreamDecoder + Send + Sync + 't>],
    elfs: &'a [LoadedElf],
) -> anyhow::Result<Step<'a>> {
    let mut decoded = None;
    let (mut incomplete, mut rejected) = (0, 0);

    for (stream_decoder, elf) in stream_decoders.iter_mut().zip(elfs) {
        match stream_decoder.decode() {
            Ok(frame) => {
                if decoded.replace((frame, &elf.locs)).is_some() {
                    bail!("more than one ELF decoded the same frame");
                }
            }
            Err(DecodeError::UnexpectedEof) => incomplete += 1,
            Err(DecodeError::Malformed) => rejected += 1,
        }
    }

    match (decoded, incomplete, rejected) {
        (Some((frame, locs)), 0, _) => Ok(Step::Decoded(frame, locs)),
        (None, incomplete, 0) if incomplete == elfs.len() => Ok(Step::NeedMoreData),
        (None, 0, rejected) if rejected == elfs.len() => Ok(Step::Malformed),
        _ => bail!("ELF decoders are out of step on the frame boundaries"),
    }
}

struct LoadedElf {
    bytes: Vec<u8>,
    table: Table,
    locs: Option<Locations>,
}

impl LoadedElf {
    async fn load(path: PathBuf) -> anyhow::Result<Self> {
        let bytes = fs::read(&path).await?;
        let table = Table::parse(&bytes)?
            .ok_or_else(|| anyhow!(".defmt data not found in {}", path.display()))?;
        let locs = table.get_locations(&bytes)?;

        // check if the locations info contains all the indicies
        let locs = if table.indices().all(|idx| locs.contains_key(&(idx as u64))) {
            Some(locs)
        } else {
            log::warn!("(BUG) location info is incomplete; it will be omitted from the output");
            None
        };

        Ok(Self { bytes, table, locs })
    }
}

/// Several ELFs can share a stream only if every frame belongs to exactly one table, which needs
/// matching encodings and disjoint defmt indices. With `same_rtt_addr`, they must also place
/// `_SEGGER_RTT` at one address, since the probe is given only the first ELF's.
fn check_elfs_compatible(elfs: &[LoadedElf], same_rtt_addr: bool) -> anyhow::Result<()> {
    let Some((first, rest)) = elfs.split_first() else {
        bail!("no ELF given");
    };
    if rest.is_empty() {
        return Ok(());
    }

    if let Some(other) = rest
        .iter()
        .find(|elf| elf.table.encoding() != first.table.encoding())
    {
        bail!(
            "ELFs use different defmt encodings ({:?} and {:?})",
            first.table.encoding(),
            other.table.encoding()
        );
    }
    if !first.table.encoding().can_recover() {
        bail!("multiple ELFs need a recoverable encoding such as rzcobs");
    }

    for (i, a) in elfs.iter().enumerate() {
        let a_indices: BTreeSet<usize> = a.table.indices().collect();
        for (j, b) in elfs.iter().enumerate().skip(i + 1) {
            if let Some(idx) = b.table.indices().find(|idx| a_indices.contains(idx)) {
                bail!(
                    "ELFs #{} and #{} both define defmt index {idx:#x}; link one image's \
                    `.defmt` section at a different base so the index ranges are disjoint",
                    i + 1,
                    j + 1
                );
            }
        }
    }

    if !same_rtt_addr {
        return Ok(());
    }
    let first_rtt = segger_rtt_addr(&first.bytes).context("ELF #1")?;
    for (i, elf) in rest.iter().enumerate() {
        let rtt = segger_rtt_addr(&elf.bytes).with_context(|| format!("ELF #{}", i + 2))?;
        if rtt != first_rtt {
            bail!(
                "ELFs #1 and #{} have different `_SEGGER_RTT` addresses ({first_rtt:#x} and \
                {rtt:#x}); all images must place the RTT control block at the same address",
                i + 2
            );
        }
    }

    Ok(())
}

/// Returns the address of the `_SEGGER_RTT` control-block symbol defined in `elf_bytes`.
fn segger_rtt_addr(elf_bytes: &[u8]) -> anyhow::Result<u64> {
    let elf = Elf::parse(elf_bytes)?;
    let rtt_symbol = elf
        .syms
        .iter()
        .find(|sym| elf.strtab.get_at(sym.st_name) == Some("_SEGGER_RTT"))
        .ok_or_else(|| anyhow!("Symbol '_SEGGER_RTT' not found in ELF file"))?;
    Ok(rtt_symbol.st_value)
}

type LocationInfo = (Option<String>, Option<u32>, Option<String>);

fn forward_to_logger(frame: &Frame, location_info: LocationInfo) {
    let (file, line, mod_path) = location_info;
    defmt_decoder::log::log_defmt(frame, file.as_deref(), line, mod_path.as_deref());
}

fn location_info(locs: &Option<Locations>, frame: &Frame, current_dir: &Path) -> LocationInfo {
    let (mut file, mut line, mut mod_path) = (None, None, None);

    let loc = locs.as_ref().map(|locs| locs.get(&frame.index()));

    if let Some(Some(loc)) = loc {
        // try to get the relative path, else the full one
        let path = loc.file.strip_prefix(current_dir).unwrap_or(&loc.file);

        file = Some(path.display().to_string());
        line = Some(loc.line as u32);
        mod_path = Some(loc.module.clone());
    }

    (file, line, mod_path)
}

/// Report version from Cargo.toml _(e.g. "0.1.4")_ and supported `defmt`-versions.
///
/// Used by `--version` flag.
#[allow(clippy::unnecessary_wraps)]
fn print_version() -> anyhow::Result<()> {
    println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
    let s = if DEFMT_VERSIONS.len() > 1 { "s" } else { "" };
    println!("supported defmt version{s}: {}", DEFMT_VERSIONS.join(", "));
    Ok(())
}
