// SPDX-FileCopyrightText: 2024 Nils Jochem
// SPDX-License-Identifier: MPL-2.0

use data::TimeLabel;
use itertools::Itertools;
use log::{debug, error, trace, warn};
use std::{
    collections::HashMap,
    fmt::Debug,
    io::Error as IoError,
    marker::Send,
    path::{Path, PathBuf},
    time::Duration,
};
use thiserror::Error;
use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    time::{error::Elapsed, interval, timeout},
};

use common::extensions::duration::Ext;

pub mod command;

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

pub mod data;

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
    /// gets the tracknumber
    ///
    /// # Errors
    /// relays [`get_track_infos`](AudacityApiGeneric::get_track_info) error
    ///
    /// # Panics
    /// when no labeltrack is found
    pub async fn get_label_track_nr<R: AsyncRead + Send + Unpin, W: AsyncWrite + Send + Unpin>(
        self,
        audacity: &mut AudacityApiGeneric<W, R>,
    ) -> Result<usize, Error> {
        Ok(match self {
            Self::LabelTrackNr(nr) => {
                audacity
                    .get_track_info()
                    .await?
                    .iter()
                    .enumerate()
                    .filter(|(_, it)| it.kind == result::Kind::Label)
                    .nth(nr)
                    .expect("no labeltrack")
                    .0
            }
            Self::TrackNr(nr) => nr,
        })
    }
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("{0}. Err: {1:?}")]
    PipeBroken(String, #[source] Option<IoError>),
    #[error("Didn't finish with OK or Failed!, {0:?}")]
    MissingOK(String),
    #[error("Failed with {0:?}")]
    AudacityErr(String), // TODO parse Error
    #[error("couldn't parse result {0:?} because {1}")]
    MalformedResult(String, #[source] MalformedCause),
    #[error("Unkown path {0:?}, {1}")]
    PathErr(PathBuf, #[source] IoError),
    #[error("timeout after {0:?}")]
    Timeout(Duration),
}

#[derive(Error, Debug)]
pub enum MalformedCause {
    #[error(transparent)]
    JSON(#[from] serde_json::Error),
    #[error(transparent)]
    Own(#[from] result::Error),
    #[error("ping returned {0:?}")]
    BadPingResult(String),
    #[error("missing line break")]
    MissingLineBreak,
}

#[derive(Debug, Error)]
pub enum LaunchError {
    #[error(transparent)]
    IO(#[from] IoError),
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
    program: String,
    #[serde(default = "Vec::new")]
    #[serde(skip_serializing_if = "Vec::is_empty")]
    arg: Vec<String>,
    /// the length of time until the process is assumed to not be a launcher. The Programm will no longer wait for an exit code.
    #[serde(
        default = "Config::default_timeout",
        skip_serializing_if = "Config::is_default_timeout",
        deserialize_with = "from_millis",
        serialize_with = "as_millis"
    )]
    timeout: Duration,
    #[serde(
        default = "Config::default_hide",
        skip_serializing_if = "Config::is_default_hide"
    )]
    hide_output: bool,
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
    /// can panic, when loading of config fails.
    ///
    /// # Errors
    /// - [`LaunchError::IO`] when executing the commant failed
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
            let mut command = tokio::process::Command::new(config.program);
            if config.hide_output {
                // TODO pipe output to logs
                command.stderr(std::process::Stdio::null());
                command.stdout(std::process::Stdio::null());
            }
            command.args(&config.arg);
            command.kill_on_drop(false);

            LaunchError::from_status_code(command.status().await?.code())
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
    /// - when the other Pipe isn't ready after waiting for the first pipe
    /// - when Ping returns false
    pub async fn new(timer: Option<Duration>) -> Result<Self, Error> {
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
        ) -> Result<P::PType, Error> {
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
                            break Err(Error::PipeBroken(
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
                        break Err(Error::PipeBroken(msg, Some(err)));
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
    ) -> Result<Self, Error> {
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
    pub async fn write_assume_empty(&mut self, command: command::NoOut<'_>) -> Result<(), Error> {
        let result = self.write_any(command.clone().into(), false).await?;
        assert_eq!(result, "", "expecting empty result for {command:?}");
        Ok(())
    }
    async fn write_assume_result(&mut self, command: command::Out<'_>) -> Result<String, Error> {
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
    ) -> Result<String, Error> {
        let timer = self.timer;
        let future = async {
            let command_str = command.to_string().replace('\n', LINE_ENDING);
            match command {
                command::Any::Out(command::Message {
                    text: _,
                    _hide_output: true,
                }) => {}
                _ => {
                    debug!("writing {command_str:?} to audacity");
                }
            }

            self.write_pipe
                .write_all(format!("{command_str}{LINE_ENDING}").as_bytes())
                .await
                .map_err(|err| {
                    Error::PipeBroken(format!("failed to send {command:?}"), Some(err))
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
    /// This can panic, when after {[`Self::ACK_START`]} somthing unexpected appears
    async fn read(&mut self, allow_empty: bool) -> Result<String, Error> {
        let mut result = Vec::new();
        loop {
            if !allow_empty {
                trace!("reading next line from audacity");
            }
            let line = match read_line(&mut self.read_pipe).await {
                Ok(Some(line)) => Ok(line),
                Ok(None) => Err(Error::PipeBroken(
                    format!("empty reader, current buffer: {:?}", result.join("\n")),
                    None,
                )),
                Err(err) => Err(Error::PipeBroken(
                    format!(
                        "failed to read next line, current buffer: {:?}",
                        result.join("\n")
                    ),
                    Some(err),
                )),
            }?;

            if !allow_empty {
                trace!("read line {line:?} from audacity");
            }

            if line.is_empty() {
                if allow_empty || !result.is_empty() {
                    break;
                }
                // skipping empty leading line
            } else {
                result.push(line);
            }
        }
        let Some(last) = result.pop() else {
            return Ok(String::new());
        };
        let result = result.join("\n");
        match last.strip_prefix(Self::ACK_START) {
            Some("OK") => {
                debug!("read '{result}' from audacity");
                Ok(result)
            }
            Some("Failed!") => Err(Error::AudacityErr(result)),
            Some(x) => panic!("need error handling for {x}"),
            None => {
                let result = if result.is_empty() {
                    last
                } else {
                    format!("{result}\n{last}")
                };
                Err(Error::MissingOK(result))
            }
        }
    }

    /// formats the error of [`maybe_timeout`] to [`Error::Timeout`]
    async fn maybe_timeout<F: std::future::Future + Send>(
        timer: Option<Duration>,
        future: F,
    ) -> Result<F::Output, Error> {
        maybe_timeout(timer, future)
            .await
            .map_err(|_err| Error::Timeout(timer.unwrap()))
    }
    /// Pings Audacity and returns if the result is correct.
    ///
    /// # Errors
    ///  - when write/send errors
    ///  - [`Error::MalformedResult`] when something other then ping is answered
    pub async fn ping(&mut self) -> Result<bool, Error> {
        self.inner_ping(false).await
    }
    async fn inner_ping(&mut self, hide_output: bool) -> Result<bool, Error> {
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
            _ => Err(Error::MalformedResult(
                result.clone(),
                MalformedCause::BadPingResult(result),
            )),
        }
    }

    /// Gets Infos of the Tracks in the currently open Project.
    ///
    /// # Errors
    ///  - when write/send errors
    ///  - [`Error::MalformedResult`] when the result can't be parsed
    pub async fn get_track_info(&mut self) -> Result<Vec<result::TrackInfo>, Error> {
        let json = self
            .write_assume_result(command::GetInfo {
                type_info: command::InfoType::Tracks,
                format: command::OutputFormat::Json,
            })
            .await?;
        serde_json::from_str::<Vec<result::TrackInfo>>(&json)
            .map_err(|e| Error::MalformedResult(json, e.into()))
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
    ) -> Result<(), Error> {
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
    pub async fn import_audio(&mut self, path: impl AsRef<Path> + Send) -> Result<(), Error> {
        let path = path
            .as_ref()
            .canonicalize()
            .map_err(|e| Error::PathErr(path.as_ref().to_path_buf(), e))?;

        self.write_assume_empty(command::Import2 { filename: &path })
            .await
    }

    /// Gets Infos of the lables in the currently open Project.
    ///
    /// # Errors
    ///  - when write/send errors
    ///  - [`Error::MalformedResult`] when the result can't be parsed
    pub async fn get_label_info(&mut self) -> Result<HashMap<usize, Vec<TimeLabel>>, Error> {
        type RawTimeLabel = (f64, f64, String);
        let json = self
            .write_assume_result(command::GetInfo {
                type_info: command::InfoType::Labels,
                format: command::OutputFormat::Json,
            })
            .await?;
        serde_json::from_str::<'_, Vec<(usize, Vec<RawTimeLabel>)>>(&json)
            .map_err(|e| Error::MalformedResult(json, e.into()))
            .map(|list| {
                list.into_iter()
                    .map(|(nr, labels)| (nr, labels.into_iter().map_into().collect_vec()))
                    .collect()
            })
    }
    /// Adds a new label track to the currently open Project.
    ///
    /// # Errors
    ///  - when write/send errors
    pub async fn add_label_track(
        &mut self,
        name: Option<impl AsRef<str> + Send>,
    ) -> Result<usize, Error> {
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
    pub async fn import_labels_from(
        &mut self,
        path: impl AsRef<Path> + Send + Sync,
        track_name: Option<impl AsRef<str> + Send>,
    ) -> Result<(), Error> {
        let nr = self.add_label_track(track_name).await?;
        let offset = Self::get_label_offset(&self.get_label_info().await?, nr);
        for (label_nr, label) in TimeLabel::read(&path)
            .map_err(|err| Error::PathErr(path.as_ref().to_path_buf(), err))?
            .into_iter()
            .enumerate()
        {
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
    ) -> Result<(), Error> {
        TimeLabel::write(
            self.get_label_info().await?.into_values().flatten(),
            &path,
            dry_run,
        )
        .map_err(|err| Error::PathErr(path.as_ref().to_path_buf(), err))?;
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
    ) -> Result<(), Error> {
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
    ) -> Result<usize, Error> {
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
    ) -> Result<usize, Error> {
        self.select(Selection::Part {
            start: label.start,
            end: label.end,
            relative_to: RelativeTo::ProjectStart,
        })
        .await?;
        self.write_assume_empty(command::AddLabel).await?;

        let predicate = |(_, candidate): &(usize, &TimeLabel)| {
            candidate.name.is_none()
                && candidate
                    .start
                    .is_near_to(label.start, Duration::from_millis(50))
                && candidate
                    .end
                    .is_near_to(label.end, Duration::from_millis(50))
        };
        let new_id = match hint {
            Some(LabelHint::LabelNr(nr)) => nr,
            Some(LabelHint::Track(track_hint)) => {
                let track_nr = track_hint.get_label_track_nr(self).await?;
                self.find_label_in_track(track_nr, predicate).await?
            }
            None => {
                let track_nr = self.get_focused_track().await?;
                self.find_label_in_track(track_nr, predicate).await?
            }
        };

        self.set_label(
            new_id,
            label.name,
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
    ) -> Result<usize, Error> {
        let labels = self.get_label_info().await?;
        let new_labels = labels.get(&track_nr).unwrap();
        let label_nr = new_labels
            .iter()
            .enumerate()
            .find(predicate)
            .unwrap_or_else(|| panic!("not enought labels in track {track_nr}, can't find label"))
            .0;
        Ok(Self::get_label_offset(&labels, track_nr) + label_nr)
    }
    fn get_label_offset(labels: &HashMap<usize, Vec<TimeLabel>>, track_hint: usize) -> usize {
        labels
            .iter()
            .filter(|(&t_nr, _)| t_nr < track_hint)
            .map(|(_, l)| l.len())
            .sum()
    }

    async fn get_focused_track(&mut self) -> Result<usize, Error> {
        Ok(self
            .get_track_info()
            .await?
            .into_iter()
            .enumerate()
            .filter(|(_, t)| t.focused)
            .exactly_one()
            .expect("no track focused")
            .0)
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
    ) -> Result<(), Error> {
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
    ) -> Result<(), Error> {
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
    use super::*;

    use tokio::io::{sink, ReadHalf, Sink, WriteHalf};
    use tokio_test::io::{Builder, Mock};

    #[allow(dead_code)]
    enum ReadMsg<'a> {
        Ok(&'a str),
        Fail(&'a str),
        Empty,
    }
    impl<'a> ReadMsg<'a> {
        fn to_string(&self, line_ending: &str) -> String {
            match self {
                ReadMsg::Empty => line_ending.to_owned(),
                ReadMsg::Fail(msg) => format!(
                    "{msg}\n{}Failed!\n\n",
                    AudacityApiGeneric::<Mock, Mock>::ACK_START
                )
                .replace('\n', line_ending),
                ReadMsg::Ok(msg) => format!(
                    "{msg}\n{}OK\n\n",
                    AudacityApiGeneric::<Mock, Mock>::ACK_START
                )
                .replace('\n', line_ending),
            }
        }
    }
    enum ExpectAction<'a> {
        Read(ReadMsg<'a>),
        Write(&'a str),
    }
    impl<'a> ExpectAction<'a> {
        #[allow(non_upper_case_globals)]
        const ReadEmpty: Self = Self::Read(ReadMsg::Empty);
        #[allow(non_snake_case)]
        const fn ReadOk(msg: &'a str) -> Self {
            Self::Read(ReadMsg::Ok(msg))
        }
        #[allow(non_snake_case)]
        const fn ReadFail(msg: &'a str) -> Self {
            Self::Read(ReadMsg::Fail(msg))
        }
    }

    async fn new_mocked_api(
        actions: impl Iterator<Item = ExpectAction<'_>> + Send,
        windows_line_ending: bool,
    ) -> AudacityApiGeneric<WriteHalf<Mock>, ReadHalf<Mock>> {
        let line_ending = if windows_line_ending { "\r\n" } else { "\n" };
        let mut builder = Builder::new();
        let iter = [
            ExpectAction::Write("Message: Text=ping\n"), // ping with empty result
            ExpectAction::ReadEmpty,
            ExpectAction::Write("Message: Text=ping\n"), // until one ping succeeds
            ExpectAction::ReadOk("ping"),
        ]
        .into_iter()
        .chain(actions);
        for action in iter {
            match action {
                ExpectAction::Read(msg) => builder.read(msg.to_string(line_ending).as_bytes()),
                ExpectAction::Write(msg) => {
                    builder.write(msg.replace('\n', LINE_ENDING).as_bytes())
                }
            };
        }
        let (read_mock, write_mock) = tokio::io::split(builder.build());

        timeout(
            Duration::from_secs(1),
            AudacityApiGeneric::with_pipes(
                read_mock,
                write_mock,
                None,
                interval(Duration::from_millis(100)),
            ),
        )
        .await
        .expect("timed out")
        .expect("failed to setup")
    }

    struct ReadHandle {
        handle: tokio_test::io::Handle,
    }
    #[allow(dead_code)]
    impl ReadHandle {
        fn expect(&mut self, msg: &ReadMsg) {
            self.handle.read(msg.to_string("\n").as_bytes());
        }
        fn expect_ok(&mut self, msg: &str) {
            self.expect(&ReadMsg::Ok(msg));
        }
        fn expect_fail(&mut self, msg: &str) {
            self.expect(&ReadMsg::Fail(msg));
        }
    }

    async fn ignore_write_api() -> (AudacityApiGeneric<Sink, Mock>, ReadHandle) {
        let (mock, handle) = Builder::new().build_with_handle();
        let mut handle = ReadHandle { handle };
        handle.expect_ok("ping");
        (
            timeout(
                Duration::from_secs(1),
                AudacityApiGeneric::with_pipes(
                    mock,
                    sink(),
                    None,
                    interval(Duration::from_millis(100)),
                ),
            )
            .await
            .expect("timed out")
            .expect("failed to setup"),
            handle,
        )
    }

    #[tokio::test]
    async fn extra_ping() {
        let mut api = new_mocked_api(
            [
                ExpectAction::Write("Message: Text=ping\n"),
                ExpectAction::ReadOk("ping"),
            ]
            .into_iter(),
            false,
        )
        .await;

        api.ping().await.unwrap();
    }
    #[tokio::test]
    async fn ping_ignore_write() {
        let (mut api, mut handle) = ignore_write_api().await;
        handle.expect_ok("ping");
        api.ping().await.unwrap();
    }

    #[tokio::test]
    async fn read_mulitline_ok() {
        let msg = "some multiline\n Message".to_owned();
        let mut api = new_mocked_api(std::iter::once(ExpectAction::ReadOk(&msg)), false).await;
        assert_eq!(msg, api.read(false).await.unwrap());
    }
    #[tokio::test]
    async fn read_mulitline_failed() {
        let msg = "some multiline\n Message".to_owned();
        let mut api = new_mocked_api(std::iter::once(ExpectAction::ReadFail(&msg)), false).await;

        assert!(matches!(
            api.read(false).await.unwrap_err(),
            Error::AudacityErr(e) if e==msg
        ));
    }
    #[tokio::test]
    async fn read_mulitline_ok_windows_line_ending() {
        let msg = "some multiline\n Message".to_owned();
        let mut api = new_mocked_api(std::iter::once(ExpectAction::ReadOk(&msg)), true).await;
        assert_eq!(msg, api.read(false).await.unwrap());
    }
    #[tokio::test]
    async fn read_mulitline_failed_windows_line_ending() {
        let msg = "some multiline\n Message".to_owned();
        let mut api = new_mocked_api(std::iter::once(ExpectAction::ReadFail(&msg)), true).await;

        assert!(matches!(
            api.read(false).await.unwrap_err(),
            Error::AudacityErr(e) if e==msg
        ));
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
