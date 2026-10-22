//! Canonical validated repository paths (`MPathElement` and `MPath`).

use std::fmt;

/// Errors returned when a repository path or path component violates canonical invariants.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathError {
    EmptyPath,
    EmptyComponent,
    LeadingSlash,
    TrailingSlash,
    DotComponent,
    DotDotComponent,
    NulByte,
    SlashInElement,
    BackslashInElement,
    WindowsDrivePrefix,
}

impl fmt::Display for PathError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PathError::EmptyPath => write!(f, "repository path must not be empty"),
            PathError::EmptyComponent => write!(f, "repository path contains an empty component"),
            PathError::LeadingSlash => write!(f, "repository path must not start with '/'"),
            PathError::TrailingSlash => write!(f, "repository path must not end with '/'"),
            PathError::DotComponent => write!(f, "repository path must not contain '.'"),
            PathError::DotDotComponent => write!(f, "repository path must not contain '..'"),
            PathError::NulByte => write!(f, "repository path must not contain NUL bytes"),
            PathError::SlashInElement => write!(f, "single path element must not contain '/'"),
            PathError::BackslashInElement => {
                write!(f, "single path element must not contain '\\\\'")
            }
            PathError::WindowsDrivePrefix => {
                write!(f, "repository path must not contain a Windows drive prefix")
            }
        }
    }
}

impl std::error::Error for PathError {}

/// A single portable directory or file name component.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MPathElement(String);

impl MPathElement {
    /// Validates and constructs an [`MPathElement`].
    pub fn new(raw: impl Into<String>) -> Result<Self, PathError> {
        let s = raw.into();
        if s.is_empty() {
            return Err(PathError::EmptyComponent);
        }
        if s.as_bytes().contains(&0) {
            return Err(PathError::NulByte);
        }
        if s.contains('/') {
            return Err(PathError::SlashInElement);
        }
        if s.contains('\\') {
            return Err(PathError::BackslashInElement);
        }
        let bytes = s.as_bytes();
        if bytes.len() >= 2 && bytes[0].is_ascii_alphabetic() && bytes[1] == b':' {
            return Err(PathError::WindowsDrivePrefix);
        }
        if s == "." {
            return Err(PathError::DotComponent);
        }
        if s == ".." {
            return Err(PathError::DotDotComponent);
        }
        Ok(Self(s))
    }

    /// Returns the component string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for MPathElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MPathElement({:?})", self.0)
    }
}

impl fmt::Display for MPathElement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A canonical, non-empty, slash-separated relative repository path (`a/b/c`).
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MPath {
    elements: Vec<MPathElement>,
    joined: String,
}

impl MPath {
    /// Parses and validates a canonical repository path string.
    pub fn new(raw: &str) -> Result<Self, PathError> {
        if raw.is_empty() {
            return Err(PathError::EmptyPath);
        }
        if raw.as_bytes().contains(&0) {
            return Err(PathError::NulByte);
        }
        if raw.starts_with('/') {
            return Err(PathError::LeadingSlash);
        }
        if raw.ends_with('/') {
            return Err(PathError::TrailingSlash);
        }

        let mut elements = Vec::new();
        for part in raw.split('/') {
            elements.push(MPathElement::new(part)?);
        }

        Ok(Self {
            elements,
            joined: raw.to_string(),
        })
    }

    /// Constructs an [`MPath`] from a non-empty list of validated [`MPathElement`]s.
    pub fn from_elements(elements: Vec<MPathElement>) -> Result<Self, PathError> {
        if elements.is_empty() {
            return Err(PathError::EmptyPath);
        }
        let mut joined = String::new();
        for (idx, el) in elements.iter().enumerate() {
            if idx > 0 {
                joined.push('/');
            }
            joined.push_str(el.as_str());
        }
        Ok(Self { elements, joined })
    }

    /// Returns the full slash-separated path string.
    pub fn as_str(&self) -> &str {
        &self.joined
    }

    /// Returns the slice of path components.
    pub fn elements(&self) -> &[MPathElement] {
        &self.elements
    }

    /// Returns the number of path components.
    pub fn depth(&self) -> usize {
        self.elements.len()
    }

    /// Returns the final component of the path.
    pub fn basename(&self) -> Option<&MPathElement> {
        self.elements.last()
    }

    /// Returns the parent directory path, or `None` if this path is at the root level.
    pub fn parent(&self) -> Option<MPath> {
        if self.elements.len() <= 1 {
            None
        } else {
            MPath::from_elements(self.elements[..self.elements.len() - 1].to_vec()).ok()
        }
    }

    /// Splits the path into its first component and the remaining subpath (if any).
    pub fn split_first(&self) -> (&MPathElement, Option<MPath>) {
        let first = &self.elements[0];
        if self.elements.len() == 1 {
            (first, None)
        } else {
            let rest = MPath::from_elements(self.elements[1..].to_vec()).ok();
            (first, rest)
        }
    }

    /// Appends a single [`MPathElement`] to this path.
    pub fn join_element(&self, elem: &MPathElement) -> MPath {
        let mut elements = self.elements.clone();
        elements.push(elem.clone());
        let mut joined = self.joined.clone();
        joined.push('/');
        joined.push_str(elem.as_str());
        MPath { elements, joined }
    }

    /// Appends another [`MPath`] to this path.
    pub fn join(&self, other: &MPath) -> MPath {
        let mut elements = self.elements.clone();
        elements.extend_from_slice(&other.elements);
        let mut joined = self.joined.clone();
        joined.push('/');
        joined.push_str(&other.joined);
        MPath { elements, joined }
    }

    /// Returns `true` if `self` is a component-wise prefix of `other` (including when `self == other`).
    pub fn is_prefix_of(&self, other: &MPath) -> bool {
        if self.elements.len() > other.elements.len() {
            return false;
        }
        self.elements
            .iter()
            .zip(other.elements.iter())
            .all(|(a, b)| a == b)
    }

    /// Returns `true` if `self` is a strict ancestor directory of `other` (`self != other`).
    pub fn is_strict_prefix_of(&self, other: &MPath) -> bool {
        self.elements.len() < other.elements.len() && self.is_prefix_of(other)
    }
}

impl fmt::Debug for MPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MPath({:?})", self.joined)
    }
}

impl fmt::Display for MPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.joined)
    }
}
