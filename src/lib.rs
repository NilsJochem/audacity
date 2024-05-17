// SPDX-FileCopyrightText: 2024 Nils Jochem
// SPDX-License-Identifier: MPL-2.0

use itertools::Itertools;
use log::{debug, trace, warn};
use std::{
    collections::HashMap, fmt::Debug, io::Error as IoError, marker::Send, path::Path,
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    time::{error::Elapsed, interval, timeout},
};

use common::extensions::duration::Ext;

pub use config::Config;
use data::{timelabel::TimeLabel, LabelHint, RelativeTo, Save, Selection, TrackHint};

pub mod command;

pub mod data {
    use std::{marker::Send, time::Duration};
    use tokio::io::{AsyncRead, AsyncWrite};

    use crate::{command, ConnectionError};

    pub mod timelabel;
    pub use timelabel::TimeLabel;

    #[derive(Debug, Clone, Copy, PartialEq, Eq, derive_more::Display)]
    pub enum RelativeTo {
        ProjectStart,
        Project,
        ProjectEnd,
        SelectionStart,
        Selection,
        SelectionEnd,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Selection {
        All,
        Stored,
        Part {
            start: Duration,
            end: Duration,
            relative_to: RelativeTo,
        },
    }
    impl From<Option<Selection>> for command::NoOut<'_> {
        fn from(value: Option<Selection>) -> Self {
            match value {
                None => command::SelectNone,
                Some(Selection::All) => command::SelectAll,
                Some(Selection::Stored) => command::SelRestore,
                Some(Selection::Part {
                    start,
                    end,
                    relative_to,
                }) => command::SelectTime {
                    start: Some(start),
                    end: Some(end),
                    relative_to,
                },
            }
        }
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum Save {
        Restore,
        Discard,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum LabelHint {
        Track(TrackHint),
        LabelNr(usize),
    }
    impl From<TrackHint> for LabelHint {
        fn from(value: TrackHint) -> Self {
            Self::Track(value)
        }
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum TrackHint {
        TrackNr(usize),
        LabelTrackNr(usize),
    }
    impl TrackHint {
        /// gets the tracknumber if it can be found
        ///
        /// # Errors
        /// relays [`get_track_infos`](AudacityApiGeneric::get_track_info) error
        pub async fn get_label_track_nr<
            R: AsyncRead + Send + Unpin,
            W: AsyncWrite + Send + Unpin,
        >(
            self,
            audacity: &mut super::AudacityApiGeneric<W, R>,
        ) -> Result<Option<usize>, ConnectionError> {
            Ok(match self {
                Self::LabelTrackNr(nr) => audacity
                    .get_track_info()
                    .await?
                    .iter()
                    .enumerate()
                    .filter(|(_, it)| it.kind == super::result::Kind::Label)
                    .nth(nr)
                    .map(|it| it.0),
                Self::TrackNr(nr) => Some(nr),
            })
        }
    }
}

pub mod config {
    use std::time::Duration;

    use common::extensions::duration::Ext;
    use itertools::Itertools;

    fn as_millis<S>(d: &Duration, ser: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        ser.serialize_u64(d.as_millis() as u64)
    }
    fn from_millis<'de, D>(ser: D) -> Result<Duration, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        use serde::de::Deserialize;
        u64::deserialize(ser).map(Duration::from_millis)
    }

    #[derive(Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
    pub struct Config {
        pub(super) program: String,
        #[serde(default = "Vec::new")]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        pub(super) arg: Vec<String>,
        /// the length of time until the process is assumed to not be a launcher. The Programm will no longer wait for an exit code.
        #[serde(
            default = "Config::default_timeout",
            skip_serializing_if = "Config::is_default_timeout",
            deserialize_with = "from_millis",
            serialize_with = "as_millis"
        )]
        pub(super) timeout: Duration,
        #[serde(
            default = "Config::default_hide",
            skip_serializing_if = "Config::is_default_hide"
        )]
        pub(super) hide_output: bool,
    }

    impl Config {
        pub fn new<Iter>(
            prog: impl AsRef<str>,
            args: Iter,
            timeout: impl Into<Option<Duration>>,
            hide_output: impl Into<Option<bool>>,
        ) -> Self
        where
            Iter: IntoIterator,
            Iter::Item: AsRef<str>,
        {
            Self {
                program: prog.as_ref().to_owned(),
                arg: args
                    .into_iter()
                    .map(|it| it.as_ref().to_owned())
                    .collect_vec(),
                timeout: timeout.into().unwrap_or(Self::default_timeout()),
                hide_output: hide_output.into().unwrap_or(Self::default_hide()),
            }
        }

        const fn default_timeout() -> Duration {
            Duration::from_millis(500)
        }
        fn is_default_timeout(it: &Duration) -> bool {
            (*it).is_near_to(Self::default_timeout(), Duration::from_millis(1))
        }

        const fn default_hide() -> bool {
            false
        }
        #[allow(clippy::trivially_copy_pass_by_ref)] // signature needed by serde
        const fn is_default_hide(it: &bool) -> bool {
            *it == Self::default_hide()
        }
    }
    impl Default for Config {
        fn default() -> Self {
            Self::new("audacity", None::<&str>, None, None)
        }
    }
}

#[cfg(windows)]
const LINE_ENDING: &str = "\r\n";
#[cfg(not(windows))]
const LINE_ENDING: &str = "\n";

#[link(name = "c")]
#[cfg(any(target_os = "linux", target_os = "macos"))]
extern "C" {
    fn geteuid() -> u32;
}
#[cfg(any(target_os = "linux", target_os = "macos"))]
fn get_uid() -> u32 {
    unsafe { geteuid() }
}

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("{0}. Err: {1:?}")]
    PipeBroken(String, #[source] Option<IoError>), // TODO parse possible sources
    #[error("Didn't finish with OK or Failed!, {0:?}")]
    MissingOK(String),
    #[error("Failed with {0:?}")]
    AudacityErr(String), // TODO parse Error
    #[error("timeout after {0:?}")]
    Timeout(Duration),
}

#[derive(Debug, Error)]
pub enum ImportLabelError {
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    Parse(#[from] data::timelabel::LabelReadError),
}
#[derive(Debug, Error)]
pub enum ExportLabelError {
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    IO(#[from] IoError),
}

#[derive(Debug, Error)]
pub enum ImportAudioError {
    #[error(transparent)]
    Connection(#[from] ConnectionError),
    #[error(transparent)]
    IO(#[from] IoError),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LaunchError {
    #[error("system limit for child processes reached")]
    ProcessLimitReached,
    #[error("couldn't find programm {0:?}")]
    UnkownCommand(String),
    #[error("failed with status code {0}")]
    Failed(i32),
    #[error("process was terminated")]
    Terminated,
}
impl LaunchError {
    const fn from_status_code(value: Option<i32>) -> Result<(), Self> {
        match value {
            Some(0) => Ok(()),
            Some(code) => Err(Self::Failed(code)),
            None => Err(Self::Terminated),
        }
    }
}
#[derive(Debug)]
#[must_use]
pub struct AudacityApiGeneric<Writer, Reader> {
    write_pipe: Writer,
    read_pipe: BufReader<Reader>,
    timer: Option<Duration>,
}

///exposes an os specific version
#[cfg(windows)]
pub type AudacityApi = AudacityApiGeneric<
    tokio::net::windows::named_pipe::NamedPipeClient,
    tokio::net::windows::named_pipe::NamedPipeClient,
>;
#[cfg(windows)]
impl AudacityApi {
    pub async fn launch(config: impl Into<Option<Config>>) -> Result<(), LaunchError> {
        todo!("stub");
    }
    pub const fn new(timer: Option<Duration>) -> Self {
        todo!("stub");
        use tokio::net::windows::named_pipe::ClientOptions;
        let options = ClientOptions::new();
        let mut poll_rate = interval(Duration::from_millis(100));

        Self::with_pipes(
            options.open(r"\\.\pipe\ToSrvPipe"),
            options.open(r"\\.\pipe\FromSrvPipe"),
            timer,
            poll_rate,
        );
    }
}

///exposes an os specific version
#[cfg(unix)]
pub type AudacityApi =
    AudacityApiGeneric<tokio::net::unix::pipe::Sender, tokio::net::unix::pipe::Receiver>;
#[cfg(unix)]
impl AudacityApi {
    const BASE_PATH: &'static str = "/tmp/audacity_script_pipe";

    /// Launches Audacity.
    ///
    /// Will return a handle to the running process or None if it did already exit.
    /// This can be ignored/dropped to keep it running until the main program stops
    /// or aborted to stop the running progress.
    ///
    /// # Panics
    /// - when loading of config fails.
    /// - when no child process can be spawned with an unkown `IOError`
    ///
    /// # Errors
    /// - [`LaunchError::ProcessLimitReached`] when child process limit is reached
    /// - [`LaunchError::UnkownCommand`] when path to command could't be found
    /// - [`LaunchError::Failed`] when the launcher exited with an statuscode != 0
    /// - [`LaunchError::Terminated`] when the launcher was terminated by a signal
    #[allow(clippy::redundant_pub_crate)] // lint is triggered inside select!
    pub async fn launch(
        config: impl Into<Option<Config>> + Send,
    ) -> Result<Option<tokio::task::JoinHandle<Result<(), LaunchError>>>, LaunchError> {
        let config = config
            .into()
            .unwrap_or_else(|| Self::load_config().unwrap());
        let mut future = Box::pin(async move {
            let mut command = tokio::process::Command::new(&config.program);
            if config.hide_output {
                // TODO pipe output to logs
                command.stderr(std::process::Stdio::null());
                command.stdout(std::process::Stdio::null());
            }
            command.args(&config.arg);
            command.kill_on_drop(false);

            LaunchError::from_status_code(
                command
                    .status()
                    .await
                    .map_err(|err| {
                        if err.kind() == std::io::ErrorKind::WouldBlock {
                            LaunchError::ProcessLimitReached
                        } else if err.raw_os_error() == Some(2) {
                            LaunchError::UnkownCommand(config.program)
                        } else {
                            panic!("handle {err} on launch")
                        }
                    })?
                    .code(),
            )
        });
        trace!("waiting for audacity launcher");
        tokio::select! {
            result = &mut future => {
                trace!("audacity launcher finished");
                match result {
                    Ok(()) => Ok(None),
                    Err(LaunchError::Failed(255)) => {
                        log::info!("assumes exitcode 255 means another Audacity instance is already running");
                        Ok(None)
                    }
                    Err(err) => Err(err),
                }
            }
            () = tokio::time::sleep(config.timeout) => {
                debug!("audacity launcher still running");
                Ok(Some(tokio::spawn(future)))
            }
        }
    }

    /// creates a new Instance of `AudacityApi` for linux.
    ///
    /// Will wait for `timer` until the pipe is ready, and saves the timer in `self`.
    /// Will also wait for ping to answer.
    ///
    /// # Errors
    /// - when a Timeout occures
    /// - when Ping returns false
    pub async fn new(timer: Option<Duration>) -> Result<Self, ConnectionError> {
        use tokio::net::unix::pipe::OpenOptions;
        trait Pipe {
            type PType;
            const NAME: &'static str;
            const WAIT: bool;

            fn get_path(uid: u32) -> String;
            fn try_open(options: &OpenOptions, path: &str) -> Result<Self::PType, IoError>;
        }
        struct R;
        impl Pipe for R {
            type PType = tokio::net::unix::pipe::Receiver;

            const NAME: &'static str = "reader pipe";
            const WAIT: bool = false;

            fn get_path(uid: u32) -> String {
                format!("{}.from.{uid}", AudacityApi::BASE_PATH)
            }
            fn try_open(options: &OpenOptions, path: &str) -> Result<Self::PType, IoError> {
                options.open_receiver(path)
            }
        }
        struct W;
        impl Pipe for W {
            type PType = tokio::net::unix::pipe::Sender;

            const NAME: &'static str = "writer pipe";
            const WAIT: bool = true;

            fn get_path(uid: u32) -> String {
                format!("{}.to.{uid}", AudacityApi::BASE_PATH)
            }
            fn try_open(options: &OpenOptions, path: &str) -> Result<Self::PType, IoError> {
                options.open_sender(path)
            }
        }

        async fn open_pipe<P: Pipe>(
            poll_rate: &mut tokio::time::Interval,
        ) -> Result<P::PType, ConnectionError> {
            let options = OpenOptions::new();
            let path = P::get_path(get_uid());
            loop {
                poll_rate.tick().await;
                match P::try_open(&options, &path) {
                    Ok(pipe) => break Ok(pipe),
                    Err(err)
                        if err.raw_os_error() == Some(6)
                            || err.kind() == std::io::ErrorKind::NotFound =>
                    {
                        //  - err = Os(6) => pipe is not connected
                        //  - kind = NotFound => pipe doesn't exist
                        if P::WAIT {
                            trace!("no {} found/connected, keep waiting", P::NAME);
                        } else {
                            break Err(ConnectionError::PipeBroken(
                                format!("no {} found/connected and will not wait", P::NAME),
                                Some(err),
                            ));
                        }
                    }
                    Err(err) => {
                        let msg = if err.kind() == std::io::ErrorKind::InvalidInput {
                            format!("expected {} file", P::NAME)
                        } else {
                            format!("failed to open {}", P::NAME)
                        };
                        break Err(ConnectionError::PipeBroken(msg, Some(err)));
                    }
                }
            }
        }

        let mut poll_rate = interval(Duration::from_millis(100));

        let writer = Self::maybe_timeout(timer, open_pipe::<W>(&mut poll_rate)).await??;
        poll_rate.reset();
        let reader = open_pipe::<R>(&mut poll_rate).await?;

        debug!("pipes found");
        poll_rate.reset();
        Self::with_pipes(reader, writer, timer, poll_rate).await
    }
}

impl<W: AsyncWrite + Send + Unpin, R: AsyncRead + Send + Unpin> AudacityApiGeneric<W, R> {
    const ACK_START: &'static str = "BatchCommand finished: ";
    fn load_config() -> Result<Config, confy::ConfyError> {
        confy::load::<Config>("audio-matcher", "audacity")
    }

    async fn with_pipes(
        reader: R,
        writer: W,
        timer: Option<Duration>,
        mut poll_rate: tokio::time::Interval,
    ) -> Result<Self, ConnectionError> {
        let mut audacity_api = Self {
            write_pipe: writer,
            read_pipe: BufReader::new(reader),
            timer,
        };
        // waiting for audacity to be ready
        let mut count = 0;
        while !audacity_api.inner_ping(count > 0).await? {
            poll_rate.tick().await;
            if count > 0 && log::log_enabled!(log::Level::Debug) {
                print!(".");
                std::io::Write::flush(&mut std::io::stdout()).unwrap();
            }
            count += 1;
        }
        Ok(audacity_api)
    }

    /// writes `command` directly to audacity, waits for a result but asserts it is empty.
    ///
    /// for commands with output use its dedicated Method. Also prefer a dedicated method it one is available
    ///
    /// # Errors
    /// when either `self.write` or `self.read` errors, or the timeout occures
    ///
    /// # Panics
    /// when a non empty result is recieved
    pub async fn write_assume_empty(
        &mut self,
        command: command::NoOut<'_>,
    ) -> Result<(), ConnectionError> {
        let result = self.write_any(command.clone().into(), false).await?;
        assert!(
            result.is_empty(),
            "expecting empty result for {command:?}, but got {result:?}"
        );
        Ok(())
    }
    async fn write_assume_result(
        &mut self,
        command: command::Out<'_>,
    ) -> Result<String, ConnectionError> {
        self.write_any(command.into(), false).await
    }
    /// writes `command` to audacity and waits for a result.
    ///
    /// applys timeout if `self.timer` is Some.
    ///
    /// forwarts `allow_no_ok` to read. This is only intendet to ping until ready
    ///
    /// one should use `write_assume_empty` or `write_assume_result`
    /// this errors when either `self.write` or `self.read` errors, or the timeout occures
    async fn write_any(
        &mut self,
        command: command::Any<'_>,
        allow_no_ok: bool,
    ) -> Result<String, ConnectionError> {
        let timer = self.timer;
        let future = async {
            let command_str = command.to_string().replace('\n', LINE_ENDING);
            match command {
                command::Any::Out(command::Message {
                    text: _,
                    _hide_output: true,
                }) => {}
                _ => debug!("writing {command_str:?} to audacity"),
            }

            self.write_pipe
                .write_all(format!("{command_str}{LINE_ENDING}").as_bytes())
                .await
                .map_err(|err| {
                    ConnectionError::PipeBroken(format!("failed to send {command:?}"), Some(err))
                })?;

            self.read(allow_no_ok).await
        };

        Self::maybe_timeout(timer, future).await?
    }
    /// Reads the next answer from audacity.
    /// When not `allow_no_ok` reads lines until {[`Self::ACK_START`]}+\["OK"|"Failed!"\]+"\n\n" is reached and returns everything before.
    /// Else will also accept just "\n".
    ///
    /// # Errors
    ///  - [`Error::PipeBroken`] when the read pipe is closed or it reads ""
    ///  - [`Error::MissingOK`] or [`Error::MalformedResult`] when it didn't recieve OK\n
    ///  - [`Error::AudacityErr`] when it recieved an "Failed!", the error will contain the Error message
    ///
    /// # Panics
    /// This can panic, when after {[`Self::ACK_START`]} neither Ok nor Failed is recieved
    async fn read(&mut self, allow_empty: bool) -> Result<String, ConnectionError> {
        let mut result = Vec::new();
        loop {
            if !allow_empty {
                trace!("reading next line from audacity");
            }
            let line = match read_line(&mut self.read_pipe).await {
                Ok(Some(line)) => line,
                Ok(None) => Err(ConnectionError::PipeBroken(
                    format!("empty reader, current buffer: {:?}", result.join("\n")),
                    None,
                ))?,
                Err(err) => Err(ConnectionError::PipeBroken(
                    format!(
                        "failed to read next line, current buffer: {:?}",
                        result.join("\n")
                    ),
                    Some(err),
                ))?,
            };

            if !allow_empty {
                trace!("read line {line:?} from audacity");
            }

            if !line.is_empty() {
                result.push(line);
                continue;
            }
            if !result.is_empty() {
                break; // return after reading empty line
            }
            if allow_empty {
                return Ok(String::new()); // return empty result early
            }
            log::warn!("skipping leading empty line");
        }
        let last = result.pop().unwrap();
        let result_str = || result.join("\n");
        match last.strip_prefix(Self::ACK_START) {
            Some("OK") => {
                let result = result_str();
                debug!("read '{result}' from audacity");
                Ok(result)
            }
            Some("Failed!") => Err(ConnectionError::AudacityErr(result_str())),
            Some(x) => panic!("need error handling for {x}"),
            None => {
                let result = if result.is_empty() {
                    last
                } else {
                    format!("{}\n{last}", result_str())
                };
                // TODO maybe panic, this should probably considered a bug in Audacity
                Err(ConnectionError::MissingOK(result))
            }
        }
    }

    /// formats the error of [`maybe_timeout`] to [`Error::Timeout`]
    async fn maybe_timeout<F: std::future::Future + Send>(
        timer: Option<Duration>,
        future: F,
    ) -> Result<F::Output, ConnectionError> {
        maybe_timeout(timer, future)
            .await
            .map_err(|_err| ConnectionError::Timeout(timer.unwrap()))
    }
    /// Pings Audacity and returns if the result is correct.
    ///
    /// # Errors
    ///  - when write/send errors
    pub async fn ping(&mut self) -> Result<bool, ConnectionError> {
        self.inner_ping(false).await
    }
    /// # Panics
    /// when something other than "ping" or "" is recieved
    async fn inner_ping(&mut self, hide_output: bool) -> Result<bool, ConnectionError> {
        let result = self
            .write_any(
                command::Message {
                    text: "ping",
                    _hide_output: hide_output,
                }
                .into(),
                true,
            )
            .await?;

        match result.as_str() {
            "ping" => Ok(true),
            "" => Ok(false),
            _ => panic!("Audacity answered Message with {result:?} when expecting \"ping\""),
        }
    }

    /// Gets Infos of the Tracks in the currently open Project.
    ///
    /// # Errors
    ///  - when write/send errors
    ///  - [`Error::MalformedResult`] when the result can't be parsed
    ///
    /// # Panics
    ///  - when the recieced track info can't be parsed
    pub async fn get_track_info(&mut self) -> Result<Vec<result::TrackInfo>, ConnectionError> {
        let json = self
            .write_assume_result(command::GetInfo {
                type_info: command::InfoType::Tracks,
                format: command::OutputFormat::Json,
            })
            .await?;
        Ok(serde_json::from_str::<Vec<result::TrackInfo>>(&json)
            .unwrap_or_else(|err| panic!("failed to read track info from {json:?} because {err}")))
    }
    /// Selects the tracks with position `tracks`.
    ///
    /// # Errors
    ///  - when write/send errors
    ///  - [`Error::AudacityErr`] when any of `tracks` is invalid
    ///
    /// # Panics
    ///  - when `tracks` is empty
    pub async fn select_tracks(
        &mut self,
        mut tracks: impl Iterator<Item = usize> + Send,
    ) -> Result<(), ConnectionError> {
        self.write_assume_empty(command::SelectTracks {
            mode: command::SelectMode::Set,
            track: tracks.next().unwrap(),
            track_count: Some(1),
        })
        .await?;
        for track in tracks {
            self.write_assume_empty(command::SelectTracks {
                mode: command::SelectMode::Add,
                track,
                track_count: Some(1),
            })
            .await?;
        }
        Ok(())
    }
    //TODO align tracks

    /// imports the audio file at `path` into a new track.
    ///
    /// # Errors
    ///  - when write/send errors
    ///  - [`Error::AudacityErr`] when path is not a valid audio file (probably)
    pub async fn import_audio(
        &mut self,
        path: impl AsRef<Path> + Send,
    ) -> Result<(), ImportAudioError> {
        let path = path.as_ref().canonicalize()?; // TODO make clear what went wrong

        Ok(self
            .write_assume_empty(command::Import2 { filename: &path })
            .await?)
    }

    /// Gets Infos of the lables in the currently open Project.
    ///
    /// # Errors
    ///  - when write/send errors
    ///
    /// # Panics
    ///  - when the recieved data can't be parsed
    ///  - if audacity sends timelabels with `start` > `end`
    pub async fn get_label_info(
        &mut self,
    ) -> Result<HashMap<usize, Vec<TimeLabel>>, ConnectionError> {
        type RawTimeLabel = (f64, f64, String);
        let json = self
            .write_assume_result(command::GetInfo {
                type_info: command::InfoType::Labels,
                format: command::OutputFormat::Json,
            })
            .await?;
        Ok(
            serde_json::from_str::<'_, Vec<(usize, Vec<RawTimeLabel>)>>(&json)
                .unwrap_or_else(|err| {
                    panic!("couldn't parse recieved labels in {json:?} because {err}")
                })
                .into_iter()
                .map(|(nr, labels)| (nr, labels.into_iter().map_into().collect_vec()))
                .collect(),
        )
    }
    /// Adds a new label track to the currently open Project.
    ///
    /// # Errors
    ///  - when write/send errors
    pub async fn add_label_track(
        &mut self,
        name: Option<impl AsRef<str> + Send>,
    ) -> Result<usize, ConnectionError> {
        self.write_assume_empty(command::NewLabelTrack).await?;
        if let Some(name) = name {
            let name = Some(name.as_ref());
            self.write_assume_empty(command::SetTrackStatus {
                name,
                selected: None,
                focused: None,
            })
            .await?;
        }

        Ok(self.get_track_info().await?.len() - 1)
    }

    /// imports labels from the file at `path`
    ///
    /// # Errors
    ///  - when write/send errors
    ///  - [`Error::PathErr`] when the file at `path` can't be read
    #[allow(clippy::missing_panics_doc)]
    pub async fn import_labels_from(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        track_name: Option<impl AsRef<str> + Send>,
    ) -> Result<(), ImportLabelError> {
        let nr = self.add_label_track(track_name).await?;
        let offset = Self::get_label_offset(&self.get_label_info().await?, nr);
        for (label_nr, label) in TimeLabel::read(&path)?.into_iter().enumerate() {
            let _ = self
                .add_label(label, Some(LabelHint::LabelNr(offset + label_nr)))
                .await?;
        }
        Ok(())
    }

    /// Export all labels to the file at `path`.
    ///
    /// Uses the format of audacitys marks file, with all tracks concatinated,
    ///
    /// # Errors
    ///  - when write/send errors
    ///  - [`Error::PathErr`] when the file at `path` can't be written to
    pub async fn export_all_labels_to(
        &mut self,
        path: impl AsRef<Path> + Send,
        dry_run: bool,
    ) -> Result<(), ExportLabelError> {
        TimeLabel::write(
            self.get_label_info().await?.into_values().flatten(),
            &path,
            dry_run,
        )?;
        Ok(())
    }
    /// Sets the `text`, `start`, `end` of the label at position `i`.
    ///
    /// When the project has multiple label tracks the position seems to be offset by all labels in tracks before.
    ///
    /// Only logs a warning if all parameters are [`None`], buts returns [`Ok`]
    ///
    /// # Errors
    ///  - when write/send errors
    ///  - [`Error::AudacityErr`] when `i` is not a valid track position
    pub async fn set_label(
        &mut self,
        i: usize,
        text: Option<impl AsRef<str> + Send>,
        start: Option<Duration>,
        end: Option<Duration>,
        selected: Option<bool>,
    ) -> Result<(), ConnectionError> {
        if text.is_none() && start.is_none() && end.is_none() && selected.is_none() {
            warn!("attempted to set_label with no values");
            return Ok(());
        }

        let text = text.as_ref().map(std::convert::AsRef::as_ref);
        self.write_assume_empty(command::SetLabel {
            label: i,
            text,
            start,
            end,
            selected,
        })
        .await
    }

    #[allow(
        unreachable_code,
        unused_variables,
        clippy::missing_errors_doc,
        clippy::missing_panics_doc
    )]
    pub async fn add_label_to(
        &mut self,
        track_nr: usize,
        label: TimeLabel,
    ) -> Result<usize, ConnectionError> {
        todo!("fix select track");
        self.select_tracks(std::iter::once(track_nr)).await?;
        self.write_assume_empty(command::SetTrackStatus {
            name: None,
            selected: None,
            focused: Some(true),
        })
        .await?;
        self.add_label(label, Some(TrackHint::TrackNr(track_nr).into()))
            .await
    }
    /// Creates a new label on track `track_nr` from `start` to `end` with Some(text).
    ///
    /// Sets the current selection to the given values and then adds a new blank Label. If text is not empty updates the label to `text`
    /// returns the postition of the label in this track
    ///
    /// # Panics
    /// - when the new label can't be located after creation
    ///
    /// # Errors
    ///  - when write/send errors
    pub async fn add_label(
        &mut self,
        label: TimeLabel,
        hint: Option<LabelHint>,
    ) -> Result<usize, ConnectionError> {
        self.select(Selection::Part {
            start: *label.start(),
            end: *label.end(),
            relative_to: RelativeTo::ProjectStart,
        })
        .await?;
        self.write_assume_empty(command::AddLabel).await?;

        let predicate = |(_, candidate): &(usize, &TimeLabel)| {
            candidate.name().is_none()
                && candidate
                    .start()
                    .is_near_to(*label.start(), Duration::from_millis(50))
                && candidate
                    .end()
                    .is_near_to(*label.end(), Duration::from_millis(50))
        };
        let new_id = match hint {
            Some(LabelHint::LabelNr(nr)) => nr,
            Some(LabelHint::Track(track_hint)) => {
                let track_nr = track_hint
                    .get_label_track_nr(self)
                    .await?
                    .expect("no label track found");
                self.find_label_in_track(track_nr, predicate)
                    .await?
                    .unwrap_or_else(|| {
                        panic!("not enought labels in track {track_nr}, can't find label")
                    })
            }
            None => {
                let track_nr = self.get_focused_track().await?.expect("no track focused");
                self.find_label_in_track(track_nr, predicate)
                    .await?
                    .unwrap_or_else(|| {
                        panic!("not enought labels in track {track_nr}, can't find label")
                    })
            }
        };

        self.set_label(
            new_id,
            label.name(),
            None,
            None,
            Some(false), // always drop selected state
        )
        .await?;

        Ok(new_id)
    }
    async fn find_label_in_track(
        &mut self,
        track_nr: usize,
        predicate: impl (FnMut(&(usize, &TimeLabel)) -> bool) + Send,
    ) -> Result<Option<usize>, ConnectionError> {
        let labels = self.get_label_info().await?;
        let new_labels = labels.get(&track_nr).unwrap();
        let label_nr = new_labels
            .iter()
            .enumerate()
            .find(predicate)
            .map(|it| Self::get_label_offset(&labels, track_nr) + it.0);
        Ok(label_nr)
    }
    fn get_label_offset(labels: &HashMap<usize, Vec<TimeLabel>>, track_hint: usize) -> usize {
        labels
            .iter()
            .filter(|(&t_nr, _)| t_nr < track_hint)
            .map(|(_, l)| l.len())
            .sum()
    }

    /// # Panics
    ///  - when multiple tracks claim to be focused
    async fn get_focused_track(&mut self) -> Result<Option<usize>, ConnectionError> {
        let mut filter = self
            .get_track_info()
            .await?
            .into_iter()
            .enumerate()
            .filter(|(_, t)| t.focused);
        let next = filter.next();
        assert!(
            filter.next().is_none(),
            "Audacity claims, there is more than one track focused"
        );
        Ok(next.map(|it| it.0))
    }

    /// selects `selection` and zooms to it
    ///
    /// can restore/discard/ignore the state of the selection after the opteration.
    /// Restoring uses `SelSave`, so anyting inside will be overwritten.
    ///
    /// # Errors
    ///  - when write/send errors
    pub async fn zoom_to(
        &mut self,
        selection: Selection,
        restore_selection: impl Into<Option<Save>> + Send,
    ) -> Result<(), ConnectionError> {
        let restore_selection = restore_selection.into();
        match restore_selection {
            Some(Save::Restore) => self.write_assume_empty(command::SelSave).await?,
            Some(Save::Discard) | None => {}
        }
        self.select(selection).await?;
        self.write_assume_empty(command::ZoomSel).await?;

        match restore_selection {
            Some(Save::Restore) => self.select(Selection::Stored).await?,
            Some(Save::Discard) => self.select(None).await?,
            None => {}
        };
        Ok(())
    }

    /// selects `selection`
    ///
    /// # Errors
    ///  - when write/send errors
    pub async fn select(
        &mut self,
        selection: impl Into<Option<Selection>> + Send,
    ) -> Result<(), ConnectionError> {
        self.write_assume_empty(selection.into().into()).await
    }
}

/// reads the next line from `read_pipe` and removes "\r?\n" from the end
/// returns `None`, when EOF was reached
///
/// # Errors
/// relays Errors of `read_line`
async fn read_line(
    mut reader: impl AsyncBufRead + Unpin + Send,
) -> Result<Option<String>, IoError> {
    let mut buf = String::new();
    Ok(if reader.read_line(&mut buf).await? == 0 {
        None
    } else {
        // remove line ending
        assert_eq!(Some('\n'), buf.pop(), "requires at least '\n' at the end");
        if buf.ends_with('\r') {
            buf.pop();
        }
        Some(buf)
    })
}

async fn maybe_timeout<F: std::future::Future + Send>(
    timer: Option<Duration>,
    future: F,
) -> Result<F::Output, Elapsed> {
    match timer {
        Some(timer) => timeout(timer, future).await,
        None => Ok(future.await),
    }
}

pub mod result {
    use serde::Deserialize;
    use thiserror::Error;

    #[derive(Debug, Error, PartialEq, Eq)]
    pub enum Error {
        #[error("Missing field {0}")]
        MissingField(&'static str),
        #[error("Unkown Kind at {0}")]
        UnkownKind(String),
    }

    #[derive(Debug, Deserialize)]
    #[allow(dead_code)]
    pub struct TrackInfo {
        pub name: String,
        #[serde(deserialize_with = "bool_from_int")]
        pub focused: bool,
        #[serde(deserialize_with = "bool_from_int")]
        pub selected: bool,
        #[serde(flatten)]
        pub kind: Kind,
    }
    impl PartialEq for TrackInfo {
        fn eq(&self, other: &Self) -> bool {
            self.name == other.name && self.kind == other.kind
        }
    }

    #[derive(Debug, Deserialize, PartialEq)]
    #[serde(tag = "kind")]
    pub enum Kind {
        #[serde(rename = "wave")]
        Wave {
            start: f64,
            end: f64,
            pan: usize,
            gain: f64,
            channels: usize,
            #[serde(deserialize_with = "bool_from_int")]
            solo: bool,
            #[serde(deserialize_with = "bool_from_int")]
            mute: bool,
        },
        #[serde(rename = "label")]
        Label,
        #[serde(rename = "time")]
        Time,
    }
    /// Deserialize 0 => false, 1 => true
    fn bool_from_int<'de, D>(deserializer: D) -> Result<bool, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match u8::deserialize(deserializer)? {
            1 => Ok(true),
            0 => Ok(false),
            other => Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Unsigned(other as u64),
                &"0 or 1",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{
        future::IntoFuture,
        ops::{Deref, DerefMut},
    };
    use tokio::{
        io::{AsyncReadExt, DuplexStream, ReadHalf, WriteHalf},
        sync::mpsc::UnboundedSender,
        task::JoinHandle,
    };

    use super::*;

    #[derive(Debug, Clone)]
    enum ReadMsg {
        Ok(String),
        Fail(String),
        Empty,
    }
    impl ReadMsg {
        fn to_string(&self, new_line: &str) -> String {
            match self {
                ReadMsg::Empty => new_line.to_owned(),
                ReadMsg::Ok(msg) => Self::make_answer(msg, "OK", new_line),
                ReadMsg::Fail(msg) => Self::make_answer(msg, "Failed!", new_line),
            }
        }
        fn make_answer(msg: &str, batch_ok: &str, new_line: &str) -> String {
            if msg == "" {
                format!("{}{batch_ok}\n\n", InnerMock::ACK_START)
            } else {
                format!("{msg}\n{}{batch_ok}\n\n", InnerMock::ACK_START)
            }
            .replace('\n', new_line)
        }
    }

    #[derive(Debug, Clone)]
    struct ExpectAction {
        recieve: String,
        answer: ReadMsg,
    }
    #[allow(dead_code)]
    impl ExpectAction {
        const fn new(recieve: String, answer: ReadMsg) -> Self {
            Self { recieve, answer }
        }
        #[allow(non_snake_case)]
        fn AnswerEmpty(recieve: impl Into<String>) -> Self {
            Self::new(recieve.into(), ReadMsg::Empty)
        }
        #[allow(non_snake_case)]
        fn AnswerOk(recieve: impl Into<String>, msg: impl Into<String>) -> Self {
            Self::new(recieve.into(), ReadMsg::Ok(msg.into()))
        }
        #[allow(non_snake_case)]
        fn AnswerFail(recieve: impl Into<String>, msg: impl Into<String>) -> Self {
            Self::new(recieve.into(), ReadMsg::Fail(msg.into()))
        }
    }

    type InnerMock = AudacityApiGeneric<WriteHalf<DuplexStream>, ReadHalf<DuplexStream>>;
    struct MockApi {
        api: InnerMock,
        queue: UnboundedSender<ExpectAction>,
        #[allow(dead_code)]
        queue_handle: JoinHandle<()>,
    }
    struct MockHandle {
        handle: DuplexStream,
        new_line: &'static str,
    }
    impl MockHandle {
        async fn read(&mut self) -> Result<String, IoError> {
            let mut buf = Vec::new();
            loop {
                let sleep_dur = if buf.is_empty() {
                    Duration::from_millis(100) // wait longer at the start of transmission
                } else {
                    Duration::from_millis(5)
                };
                tokio::select! {
                    res = self.handle.read_buf(&mut buf) => {
                        match res? {
                            0 => {
                                println!("nothing to read");
                                break;
                            }
                            _read_bytes => {}
                        }
                    }
                    _ = tokio::time::sleep(sleep_dur) => {
                        if buf.is_empty() {
                            panic!("expected to read, but only waited")
                        }
                        break; // reader empty
                    }
                }
            }

            Ok(String::from_utf8(buf).unwrap_or_else(|err| {
                panic!("no valid string was returned, but got {:?}", err.as_bytes())
            }))
        }
        async fn write(&mut self, msg: &ReadMsg) -> Result<(), IoError> {
            self.handle
                .write_all(msg.to_string(self.new_line).as_bytes())
                .await
        }

        async fn expect(&mut self, expect: &ExpectAction) -> Result<(), IoError> {
            let read = self.read().await?;
            let expect_str = expect.recieve.replace('\n', LINE_ENDING);
            assert_eq!(read, expect_str, "expected to read <left>, but got <right>");
            self.write(&expect.answer).await
        }
    }
    impl Deref for MockApi {
        type Target = InnerMock;

        fn deref(&self) -> &Self::Target {
            &self.api
        }
    }
    impl DerefMut for MockApi {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.api
        }
    }
    impl Drop for MockApi {
        fn drop(&mut self) {
            self.queue_handle.abort();
        }
    }
    impl MockApi {
        async fn new(windows_new_line: bool) -> Self {
            let (api, handle) = tokio::io::duplex(64);
            let (q_tx, q_rx) = tokio::sync::mpsc::unbounded_channel();

            let mut handle = MockHandle {
                handle,
                new_line: if windows_new_line { "\r\n" } else { "\n" },
            };
            let api = tokio::spawn(async {
                let (api_rx, api_tx) = tokio::io::split(api);
                AudacityApiGeneric::with_pipes(
                    api_rx,
                    api_tx,
                    Some(Duration::from_secs(1)),
                    tokio::time::interval(Duration::from_millis(100)),
                )
                .await
            });

            handle
                .expect(&ExpectAction::AnswerEmpty("Message: Text=ping\n"))
                .await
                .unwrap_or_else(|_| panic!("failed to answer empty startup ping"));
            handle
                .expect(&ExpectAction::AnswerOk("Message: Text=ping\n", "ping"))
                .await
                .unwrap_or_else(|_| panic!("failed to answer startup ping"));

            Self {
                api: api
                    .into_future()
                    .await
                    .expect("failed to join api")
                    .unwrap_or_else(|err| panic!("failed to create api with {err:?}")),
                queue: q_tx,
                queue_handle: tokio::spawn(async move {
                    let mut handle = handle;
                    let mut q_rx = q_rx;
                    while let Some(action) = q_rx.recv().await {
                        handle
                            .expect(&action)
                            .await
                            .unwrap_or_else(|_| panic!("failed to do {action:?}"));
                    }
                }),
            }
        }
        fn expect(&mut self, action: ExpectAction) {
            self.queue
                .send(action)
                .expect("failed to send next expected action, channel closed")
        }
    }

    #[tokio::test]
    async fn setup() {
        let _ = MockApi::new(false).await;
    }
    #[tokio::test]
    async fn extra_ping() {
        let mut api = MockApi::new(false).await;

        api.expect(ExpectAction::AnswerEmpty("Message: Text=ping\n"));
        assert!(
            !api.ping().await.expect("ping failed"),
            "ping should not be recieved"
        );
        api.expect(ExpectAction::AnswerOk("Message: Text=ping\n", "ping"));
        assert!(
            api.ping().await.expect("ping failed"),
            "ping should not be recieved"
        );
    }
    #[tokio::test]
    async fn read_mulitline_ok() {
        let msg = "some multiline\n Message";
        let mut api = MockApi::new(false).await;
        api.expect(ExpectAction::AnswerOk(
            format!("Message: Text=\"{msg}\"\n"),
            msg,
        ));
        // let mut api = new_mocked_api(std::iter::once(ExpectAction::AnswerOk(&msg)), false).await;

        assert_eq!(
            msg,
            api.write_assume_result(command::Message {
                text: &msg,
                _hide_output: false
            })
            .await
            .unwrap()
        );
    }

    mod config {
        use std::time::Duration;

        use crate::Config;

        #[test]
        fn read() {
            let conf = confy::load_path("res/config.toml").unwrap();
            assert_eq!(
                Config::new("program", ["arg"], Duration::from_secs(1), true),
                conf
            );
        }
        #[test]
        fn read_defaults() {
            let conf = confy::load_path("res/empty_config.toml").unwrap();
            assert_eq!(Config::new("program", None::<&str>, None, None), conf);
        }
    }
}
