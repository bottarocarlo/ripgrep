/*!
Support for rewriting the files that ripgrep searches.

By default, `-r/--replace` only changes what ripgrep *prints*. When
`-W/--write` is given as well, the same replacement is also applied to the
files themselves. This module implements that rewriting.

The rewriting is done as a second pass over a haystack, after it has already
been searched and printed. Doing it this way means printing stays byte-for-byte
identical to what it would have been without `-W/--write`, and it means we only
pay for reading and rewriting a file once we already know it has a match.
*/

use std::{io, path::Path};

use grep::{
    matcher::{Captures, Matcher},
    searcher::{Searcher, Sink, SinkError, SinkMatch},
};

/// A replacement that is applied to the contents of the files searched.
#[derive(Clone, Debug)]
pub(crate) struct Replacer {
    replacement: Vec<u8>,
}

impl Replacer {
    /// Create a replacer that substitutes every match with `replacement`.
    ///
    /// Capture group references in `replacement` are interpolated in exactly
    /// the same way that ripgrep's printers interpolate them.
    pub(crate) fn new(replacement: Vec<u8>) -> Replacer {
        Replacer { replacement }
    }

    /// Rewrite the file at `path` such that every match reported by `searcher`
    /// (using `matcher`) is replaced by this replacer's replacement.
    ///
    /// The number of replacements made is returned. When no replacement is
    /// made, or when the replacement leaves the contents unchanged, the file
    /// is not touched at all.
    ///
    /// Note that this searches `path` a second time. Callers should only call
    /// this once they know that `path` actually contains a match.
    pub(crate) fn replace_path<M: Matcher>(
        &self,
        matcher: M,
        searcher: &mut Searcher,
        path: &Path,
    ) -> io::Result<u64> {
        let haystack = std::fs::read(path)?;
        let caps = matcher.new_captures().map_err(io::Error::error_message)?;
        let mut sink = ReplaceSink {
            matcher: &matcher,
            replacement: &self.replacement,
            haystack: &haystack,
            caps,
            dst: Vec::with_capacity(haystack.len()),
            last_end: 0,
            count: 0,
            binary: false,
        };
        searcher.search_slice(&matcher, &haystack, &mut sink)?;
        let Some((dst, count)) = sink.into_replacement() else {
            log::trace!("{}: binary file, not rewriting", path.display());
            return Ok(0);
        };
        if count == 0 || dst == haystack {
            return Ok(count);
        }
        write_atomically(path, &dst)?;
        Ok(count)
    }
}

/// A sink that rebuilds a haystack with each of its matches replaced.
struct ReplaceSink<'a, M: Matcher> {
    matcher: &'a M,
    replacement: &'a [u8],
    /// The contents of the file as they exist on disk.
    haystack: &'a [u8],
    /// Scratch space for capture group locations.
    caps: M::Captures,
    /// The rewritten contents, built up as matches are reported.
    dst: Vec<u8>,
    /// How much of `haystack` has been copied to `dst` so far.
    last_end: usize,
    /// The number of replacements made so far.
    count: u64,
    /// Whether binary data was detected in the haystack.
    binary: bool,
}

impl<'a, M: Matcher> ReplaceSink<'a, M> {
    /// Consume this sink and return the rewritten contents along with the
    /// number of replacements made.
    ///
    /// `None` is returned when the haystack turned out to be binary, in which
    /// case it should be left alone.
    fn into_replacement(mut self) -> Option<(Vec<u8>, u64)> {
        if self.binary {
            return None;
        }
        // Everything after the last match is unchanged.
        self.dst.extend_from_slice(&self.haystack[self.last_end..]);
        Some((self.dst, self.count))
    }
}

impl<'a, M: Matcher> Sink for ReplaceSink<'a, M> {
    type Error = io::Error;

    fn matched(
        &mut self,
        searcher: &Searcher,
        mat: &SinkMatch<'_>,
    ) -> Result<bool, io::Error> {
        let start =
            usize::try_from(mat.absolute_byte_offset()).unwrap_or(usize::MAX);
        let end = start.saturating_add(mat.bytes().len());
        // The searcher reports offsets into whatever it actually searched,
        // which is only the same as the bytes on disk when the haystack was
        // used as-is. If they don't line up---because the haystack was
        // transcoded from another encoding, or because NUL bytes were
        // converted to line terminators---then splicing the replacement back
        // into the file would corrupt it. So refuse to write anything at all.
        if start < self.last_end
            || self.haystack.get(start..end) != Some(mat.bytes())
        {
            return Err(io::Error::error_message(
                "cannot rewrite this file in place because the bytes searched \
                 do not correspond to the bytes on disk (this happens when \
                 the haystack is transcoded from another encoding, or when it \
                 contains binary data)",
            ));
        }

        // Everything between the previous match and this one is unchanged.
        self.dst.extend_from_slice(&self.haystack[self.last_end..start]);
        self.last_end = end;

        // When searching line by line, the regex never gets to see the line
        // terminator, so hold it back and re-append it once the replacement is
        // done. This mirrors what the printers do.
        let (bytes, line_term) =
            if searcher.multi_line_with_matcher(self.matcher) {
                (mat.bytes(), &[][..])
            } else {
                split_line_terminator(searcher, mat.bytes())
            };

        let ReplaceSink {
            matcher,
            replacement,
            ref mut caps,
            ref mut dst,
            ref mut count,
            ..
        } = *self;
        matcher
            .replace_with_captures(bytes, caps, dst, |caps, dst| {
                *count += 1;
                caps.interpolate(
                    |name| matcher.capture_index(name),
                    bytes,
                    replacement,
                    dst,
                );
                true
            })
            .map_err(io::Error::error_message)?;
        self.dst.extend_from_slice(line_term);
        Ok(true)
    }

    fn binary_data(
        &mut self,
        _searcher: &Searcher,
        _binary_byte_offset: u64,
    ) -> Result<bool, io::Error> {
        // Rewriting a binary file is almost never what anyone wants, and we
        // can only have searched part of it anyway. Give up on this haystack.
        // (Binary detection is disabled by -a/--text, so that flag still lets
        // one rewrite binary files.)
        self.binary = true;
        Ok(false)
    }
}

/// Split `bytes` into its content and its trailing line terminator, if any.
fn split_line_terminator<'h>(
    searcher: &Searcher,
    bytes: &'h [u8],
) -> (&'h [u8], &'h [u8]) {
    let line_term = searcher.line_terminator();
    let mut end = bytes.len();
    if end > 0 && bytes[end - 1] == line_term.as_byte() {
        end -= 1;
        if line_term.is_crlf() && end > 0 && bytes[end - 1] == b'\r' {
            end -= 1;
        }
    }
    bytes.split_at(end)
}

/// Replace the contents of `path` with `contents`.
///
/// The new contents are written to a temporary file in the same directory and
/// then renamed over `path`. This way, an interrupted or failed write can't
/// leave a half-rewritten file behind.
fn write_atomically(path: &Path, contents: &[u8]) -> io::Result<()> {
    use std::io::Write;

    let tmp_path = temp_path(path);
    let result = (|| -> io::Result<()> {
        let mut file = std::fs::File::create(&tmp_path)?;
        file.write_all(contents)?;
        file.flush()?;
        // A freshly created file doesn't inherit the permissions of the file
        // we're about to replace, so copy them over. This is best effort: it
        // isn't worth failing the whole write over.
        if let Ok(meta) = std::fs::metadata(path) {
            let _ = std::fs::set_permissions(&tmp_path, meta.permissions());
        }
        std::fs::rename(&tmp_path, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&tmp_path);
    }
    result
}

/// Returns a path, in the same directory as `path`, that a new version of
/// `path` can be written to before being renamed into place.
///
/// The name only needs to be unique among the searches happening concurrently
/// in this process and in any other ripgrep processes running at the same
/// time.
fn temp_path(path: &Path) -> std::path::PathBuf {
    use std::{
        ffi::{OsStr, OsString},
        sync::atomic::{AtomicU64, Ordering},
    };

    static COUNT: AtomicU64 = AtomicU64::new(0);

    let count = COUNT.fetch_add(1, Ordering::Relaxed);
    let mut name = OsString::from(".");
    name.push(path.file_name().unwrap_or_else(|| OsStr::new("rg")));
    name.push(format!(".rg-tmp-{}-{count}", std::process::id()));
    match path.parent() {
        None => std::path::PathBuf::from(name),
        Some(parent) => parent.join(name),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Runs a replacement over `haystack` and returns the rewritten contents
    /// along with the number of replacements made.
    fn replace(
        pattern: &str,
        replacement: &str,
        haystack: &str,
    ) -> (String, u64) {
        replace_with(
            grep::searcher::SearcherBuilder::new().build(),
            pattern,
            replacement,
            haystack,
        )
    }

    /// Like `replace`, but with a caller provided searcher.
    fn replace_with(
        mut searcher: Searcher,
        pattern: &str,
        replacement: &str,
        haystack: &str,
    ) -> (String, u64) {
        // Mirror how ripgrep itself builds a matcher. In particular, giving
        // the matcher a line terminator is what tells the searcher it can
        // work line by line, so it must only be set when not searching across
        // lines. See `HiArgs::matcher_rust`.
        let mut builder = grep::regex::RegexMatcherBuilder::new();
        builder.multi_line(true);
        if !searcher.multi_line() {
            builder
                .line_terminator(Some(searcher.line_terminator().as_byte()))
                .dot_matches_new_line(false);
            if searcher.line_terminator().is_crlf() {
                builder.crlf(true);
            }
        }
        let matcher = builder.build(pattern).unwrap();
        let caps = matcher.new_captures().unwrap();
        let mut sink = ReplaceSink {
            matcher: &matcher,
            replacement: replacement.as_bytes(),
            haystack: haystack.as_bytes(),
            caps,
            dst: vec![],
            last_end: 0,
            count: 0,
            binary: false,
        };
        searcher
            .search_slice(&matcher, haystack.as_bytes(), &mut sink)
            .unwrap();
        let (dst, count) = sink.into_replacement().unwrap();
        (String::from_utf8(dst).unwrap(), count)
    }

    #[test]
    fn simple() {
        let (got, count) = replace("old", "new", "old\nkeep\nold\n");
        assert_eq!("new\nkeep\nnew\n", got);
        assert_eq!(2, count);
    }

    #[test]
    fn many_matches_on_one_line() {
        let (got, count) = replace("old", "new", "old old old\n");
        assert_eq!("new new new\n", got);
        assert_eq!(3, count);
    }

    #[test]
    fn no_match_leaves_contents_alone() {
        let (got, count) = replace("nada", "new", "old\nkeep\n");
        assert_eq!("old\nkeep\n", got);
        assert_eq!(0, count);
    }

    /// The line terminator is held back from the regex, so `$` anchors and
    /// `.` behave the same way they do when printing.
    #[test]
    fn line_terminator_is_preserved() {
        let (got, count) = replace("old$", "new", "old\nold");
        assert_eq!("new\nnew", got);
        assert_eq!(2, count);

        let (got, count) = replace(".+", "x", "ab\ncd\n");
        assert_eq!("x\nx\n", got);
        assert_eq!(2, count);
    }

    /// A haystack with no trailing line terminator still round trips.
    #[test]
    fn no_trailing_line_terminator() {
        let (got, count) = replace("old", "new", "keep\nold");
        assert_eq!("keep\nnew", got);
        assert_eq!(1, count);
    }

    #[test]
    fn capture_groups_are_interpolated() {
        let (got, count) =
            replace(r"(\w+)=(\w+)", "$2=$1", "foo=bar\nbaz=quux\n");
        assert_eq!("bar=foo\nquux=baz\n", got);
        assert_eq!(2, count);

        let (got, count) = replace(r"(?<key>\w+)=\w+", "${key}", "foo=bar\n");
        assert_eq!("foo\n", got);
        assert_eq!(1, count);
    }

    /// An empty replacement deletes the matched text, but not the line.
    #[test]
    fn empty_replacement() {
        let (got, count) = replace("old", "", "old keep\n");
        assert_eq!(" keep\n", got);
        assert_eq!(1, count);
    }

    #[test]
    fn crlf_line_terminator_is_preserved() {
        let searcher = grep::searcher::SearcherBuilder::new()
            .line_terminator(grep::matcher::LineTerminator::crlf())
            .build();
        let (got, count) =
            replace_with(searcher, "old$", "new", "old\r\nkeep\r\n");
        assert_eq!("new\r\nkeep\r\n", got);
        assert_eq!(1, count);
    }

    /// With -U/--multiline, a single reported match can span several lines.
    #[test]
    fn multiline() {
        let searcher =
            grep::searcher::SearcherBuilder::new().multi_line(true).build();
        let (got, count) =
            replace_with(searcher, "(?s)a.+?c", "X", "a\nb\nc\nkeep\n");
        assert_eq!("X\nkeep\n", got);
        assert_eq!(1, count);
    }

    /// --max-count limits how many matches the searcher reports, and so also
    /// how many of them get replaced.
    #[test]
    fn max_count_limits_replacements() {
        let searcher = grep::searcher::SearcherBuilder::new()
            .max_matches(Some(1))
            .build();
        let (got, count) = replace_with(searcher, "old", "new", "old\nold\n");
        assert_eq!("new\nold\n", got);
        assert_eq!(1, count);
    }

    /// Inverted matching reports the lines that *don't* match, and those lines
    /// have nothing in them to replace.
    #[test]
    fn invert_match_replaces_nothing() {
        let searcher =
            grep::searcher::SearcherBuilder::new().invert_match(true).build();
        let (got, count) = replace_with(searcher, "old", "new", "old\nkeep\n");
        assert_eq!("old\nkeep\n", got);
        assert_eq!(0, count);
    }

    #[test]
    fn temp_path_is_in_the_same_directory() {
        let path = Path::new("foo/bar/quux.txt");
        let tmp = temp_path(path);
        assert_eq!(Some(Path::new("foo/bar")), tmp.parent());
        assert_ne!(path.file_name(), tmp.file_name());

        // A bare file name has no directory to be relative to.
        let tmp = temp_path(Path::new("quux.txt"));
        assert_eq!(None, tmp.parent().filter(|p| !p.as_os_str().is_empty()));
    }

    #[test]
    fn temp_paths_are_unique() {
        let path = Path::new("quux.txt");
        assert_ne!(temp_path(path), temp_path(path));
    }
}
