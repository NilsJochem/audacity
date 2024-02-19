// SPDX-FileCopyrightText: 2024 Nils Jochem
// SPDX-License-Identifier: MPL-2.0

use itertools::Itertools;
use std::{path::Path, str::FromStr, time::Duration};
use thiserror::Error;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LabelParseError {
    #[error("Need at lest two tab seperated elements")]
    MissingElement,
    #[error("Failed to parse start Duration")]
    StartDuratrionParseError,
    #[error("Failed to parse end Duration")]
    EndDuratrionParseError,
    #[error("start needs to be for end, but got start:{start:?} > end:{end:?}")]
    EndBeforStart { start: Duration, end: Duration },
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum LabelReadError {
    #[error("{1} in {0:?}")]
    Parse(String, #[source] LabelParseError),
    #[error("Path not found")]
    PathNotFound,
    #[error("Permission denied")]
    PermissionDenied,
}
#[allow(clippy::fallible_impl_from)] // it is considered a Bug to fail here. Such cases need new Enum Variants
impl From<std::io::Error> for LabelReadError {
    fn from(value: std::io::Error) -> Self {
        use std::io::ErrorKind;
        match value.kind() {
            ErrorKind::NotFound => Self::PathNotFound,
            ErrorKind::PermissionDenied => Self::PermissionDenied,
            _ => panic!("unkown IoError {value:?} when reading labelfile"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, derive_more::Display)]
#[display(
    fmt = "{:.4}\t{:.4}\t{}",
    "start.as_secs_f64()",
    "end.as_secs_f64()",
    "name.as_ref().map_or(\"\", String::as_str)"
)]
pub struct TimeLabel {
    pub(crate) start: Duration,
    pub(crate) end: Duration,
    pub(crate) name: Option<String>,
}

impl TimeLabel {
    /// creates a new [`Timelabel`] with the given values
    ///
    /// # Panics
    /// panics if start is after end
    #[must_use]
    pub fn new<S: AsRef<str>>(start: Duration, end: Duration, name: impl Into<Option<S>>) -> Self {
        Self::try_new(start, end, name).expect("start needs to be befor end")
    }
    /// creates a new [`Timelabel`] with the given values or None if `start` is after `end`
    #[must_use]
    pub fn try_new<S: AsRef<str>>(
        start: Duration,
        end: Duration,
        name: impl Into<Option<S>>,
    ) -> Option<Self> {
        (start <= end).then(|| Self::new_unchecked(start, end, name))
    }
    /// creates a new [`Timelabel`] with the given values
    ///
    /// `start` needs to be before `end`
    pub fn new_unchecked<S: AsRef<str>>(
        start: Duration,
        end: Duration,
        name: impl Into<Option<S>>,
    ) -> Self {
        Self {
            start,
            end,
            name: name
                .into()
                .filter(|it| !it.as_ref().is_empty())
                .map(|it| it.as_ref().to_owned()),
        }
    }

    /// writes the labels of `labels` into `path` in a format of audacitys text mark file
    /// use `dry_run` to simulate the operation
    ///
    /// # Errors
    /// forwards the [`std::io::Error`] of writing `path`
    pub fn write<Iter>(
        labels: Iter,
        path: impl AsRef<Path>,
        dry_run: bool,
    ) -> Result<(), std::io::Error>
    where
        Iter: IntoIterator<Item = Self>,
    {
        let out = labels.into_iter().map(|it| it.to_string()).join("\n");

        if dry_run {
            println!("writing: \"\"\"\n{out}\n\"\"\" > {:?}", path.as_ref());
        } else {
            std::fs::write(&path, out)?;
        }
        Ok(())
    }

    /// reads the labels of `path` in a format of audacitys text mark file
    ///
    /// will just log a warning if a label couldn't be parsed
    ///
    /// # Errors
    /// forwards the [`std::io::Error`] of reading `path`
    pub fn read(path: impl AsRef<Path>) -> Result<Vec<Self>, LabelReadError> {
        std::fs::read_to_string(&path)?
            .lines()
            .filter(|it| !it.trim_start().starts_with('#'))
            .map(|line| {
                line.parse()
                    .map_err(|err| LabelReadError::Parse(line.to_owned(), err))
            })
            .collect::<Result<_, _>>()
    }

    /// returns a reference to start
    pub const fn start(&self) -> &Duration {
        &self.start
    }
    /// returns a reference to end
    pub const fn end(&self) -> &Duration {
        &self.end
    }
    /// returns a reference to name
    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }
    /// updates the name of `self`
    pub fn set_name<S: AsRef<str>>(&mut self, name: impl Into<Option<S>>) {
        *self = Self::new_unchecked(self.start, self.end, name);
    }
}

impl FromStr for TimeLabel {
    type Err = LabelParseError;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        fn parse_duration(
            part: &str,
            err: LabelParseError,
        ) -> Result<Duration, <TimeLabel as FromStr>::Err> {
            part.parse::<f64>()
                .map_err(|_| err)
                .map(Duration::from_secs_f64)
        }
        let (start, end, name) = value
            .splitn(3, '\t')
            .collect_tuple::<(_, _, _)>()
            .ok_or(LabelParseError::MissingElement)?;
        let start = parse_duration(start, LabelParseError::StartDuratrionParseError)?;
        let end = parse_duration(end, LabelParseError::EndDuratrionParseError)?;
        Self::try_new(start, end, name).ok_or(LabelParseError::EndBeforStart { start, end })
    }
}

impl From<(f64, f64, String)> for TimeLabel {
    fn from(value: (f64, f64, String)) -> Self {
        Self::new(
            Duration::from_secs_f64(value.0),
            Duration::from_secs_f64(value.1),
            value.2,
        )
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    #[test]
    fn label_to_str() {
        assert_eq!(
            "2.3457\t30.0000\ttest name",
            TimeLabel::new(
                Duration::from_secs_f64(2.345_678_9),
                Duration::from_secs(30),
                "test name",
            )
            .to_string()
        );
        assert_eq!(
            "2.0000\t3.0000\t",
            TimeLabel::new::<&str>(Duration::from_secs(2), Duration::from_secs(3), None)
                .to_string()
        );
    }

    #[test]
    fn str_to_label() {
        assert_eq!(
            Ok(TimeLabel::new(
                Duration::from_secs(3),
                Duration::from_secs_f64(4.56789),
                "some title"
            )),
            "3.000000000\t4.56789\tsome title".parse()
        );
    }
}
