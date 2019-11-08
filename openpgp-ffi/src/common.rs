// Common code for sequoia-openpgp-ffi and sequoia-ffi.
extern crate crc16;

use std::collections::hash_map::{DefaultHasher, RandomState};
use std::hash::BuildHasher;

macro_rules! trace {
    ( $TRACE:expr, $fmt:expr, $($pargs:expr),* ) => {
        if $TRACE {
            eprintln!($fmt, $($pargs),*);
        }
    };
    ( $TRACE:expr, $fmt:expr ) => {
        trace!($TRACE, $fmt, );
    };
}

macro_rules! tracer {
    ( $TRACE:expr, $func:expr, $indent:expr ) => {
        // Currently, Rust doesn't support $( ... ) in a nested
        // macro's definition.  See:
        // https://users.rust-lang.org/t/nested-macros-issue/8348/2
        macro_rules! t {
            ( $fmt:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, $fmt) };
            ( $fmt:expr, $a:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a)) };
            ( $fmt:expr, $a:expr, $b:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a, $b)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a, $b, $c)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a, $b, $c, $d)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a, $b, $c, $d, $e)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a, $b, $c, $d, $e, $f)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j)) };
            ( $fmt:expr, $a:expr, $b:expr, $c:expr, $d:expr, $e:expr, $f:expr, $g:expr, $h:expr, $i:expr, $j:expr, $k:expr ) =>
            { trace!($TRACE, "{}{}: {}", &""[..], $func, format!($fmt, $a, $b, $c, $d, $e, $f, $g, $h, $i, $j, $k)) };
        }
    };
    ( $TRACE:expr, $func:expr ) => {
        tracer!( $TRACE, $func, 0)
    };
}


/// A very simple profiling tool.
///
/// Note: don't ever profile code that has not been compiled in
/// release mode.  There can be orders of magnitude difference in
/// execution time between it and debug mode!
///
/// This macro measures the wall time it takes to execute the block.
/// If the time is at least $ms_threshold (in milli-seconds), then it
/// displays the output on stderr.  The output is prefixed with label,
/// if it is provided.
///
/// ```
/// let result = time_it!("Some code", 10, {
///     // Some code.
///     5
/// });
/// assert_eq!(result, 5);
/// ```
#[allow(unused_macros)]
macro_rules! time_it {
    ( $label:expr, $ms_threshold:expr, $body:expr ) => {{
        use std::time::{SystemTime, Duration};

        // We use drop so that code that uses non-local exits (e.g.,
        // using break 'label) still works.
        struct Timer {
            start: SystemTime,
        };
        impl Drop for Timer {
            fn drop(&mut self) {
                let elapsed = self.start.elapsed();
                if elapsed.clone().unwrap_or(Duration::from_millis($ms_threshold))
                    >= Duration::from_millis($ms_threshold)
                {
                    if $label.len() > 0 {
                        eprint!("{}:", $label);
                    }
                    eprintln!("{}:{}: {:?}", file!(), line!(), elapsed);
                }
            }
        }

        let _start = Timer { start: SystemTime::now() };
        $body
    }};
    ( $label:expr, $body:expr ) => {
        time_it!($label, 0, $body)
    };
    ( $body:expr ) => {
        time_it!("", $body)
    };
}


/* Canonical free().  */

/// Transfers ownership from C to Rust, then frees the object.
///
/// NOP if called with NULL.
macro_rules! ffi_free {
    ($name:ident) => {{
        if let Some(ptr) = $name {
            unsafe {
                drop(Box::from_raw(ptr))
            }
        }
    }};
}

/* Parameter handling.  */

/// Transfers ownership from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_move {
    ($name:expr) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            Box::from_raw($name)
        }
    }};
}

/// Transfers a reference from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_ref {
    ($name:ident) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            &*$name
        }
    }};
}

/// Transfers a mutable reference from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_ref_mut {
    ($name:ident) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            &mut *$name
        }
    }};
}

/// Transfers a reference to a string from C to Rust.
///
/// # Panics
///
/// Panics if called with NULL.
macro_rules! ffi_param_cstr {
    ($name:expr) => {{
        if $name.is_null() {
            panic!("Parameter {} is NULL", stringify!($name));
        }
        unsafe {
            ::std::ffi::CStr::from_ptr($name)
        }
    }};
}

/* Return value handling.  */

/// Duplicates a string similar to strndup(3).
#[allow(dead_code)]
pub(crate) fn strndup(src: &[u8]) -> Option<*mut libc::c_char> {
    if src.contains(&0) {
        return None;
    }

    let l = src.len() + 1;
    let s = unsafe {
        ::std::slice::from_raw_parts_mut(libc::malloc(l) as *mut u8, l)
    };
    &mut s[..l - 1].copy_from_slice(src);
    s[l - 1] = 0;

    Some(s.as_mut_ptr() as *mut libc::c_char)
}

/// Transfers a string from Rust to C, allocating it using malloc.
///
/// # Panics
///
/// Panics if the given string contains a 0.
macro_rules! ffi_return_string {
    ($name:expr) => {{
        let string = $name;
        let bytes: &[u8] = string.as_ref();
        ::strndup(bytes).expect(
            &format!("Returned string {} contains a 0 byte.", stringify!($name))
        )
    }};
}

/// Transfers a string from Rust to C, allocating it using malloc.
///
/// # Panics
///
/// Does *NOT* panic if the given string contains a 0, but returns
/// `NULL`.
macro_rules! ffi_return_maybe_string {
    ($name:expr) => {{
        let string = $name;
        let bytes: &[u8] = string.as_ref();
        ::strndup(bytes).unwrap_or(::std::ptr::null_mut())
    }};
}

/* Error handling with implicit error return argument.  */

/// Emits local macros for error handling that use the given context
/// to store complex errors.
macro_rules! ffi_make_fry_from_errp {
    ($errp:expr) => {
        /// Like try! for ffi glue.
        ///
        /// Evaluates the given expression.  On success, evaluate to
        /// `Status.Success`.  On failure, stashes the error in the
        /// context and evaluates to the appropriate Status code.
        #[allow(unused_macros)]
        macro_rules! ffi_try_status {
            ($expr:expr) => {
                match $expr {
                    Ok(_) => ::error::Status::Success,
                    Err(e) => {
                        use MoveIntoRaw;
                        use failure::Error;
                        let status = ::error::Status::from(&e);
                        if let Some(errp) = $errp {
                            let e : Error = e.into();
                            *errp = e.move_into_raw();
                        }
                        status
                    },
                }
            };
        }

        /// Like try! for ffi glue.
        ///
        /// Unwraps the given expression.  On failure, stashes the
        /// error in the context and returns $or.
        #[allow(unused_macros)]
        macro_rules! ffi_try_or {
            ($expr:expr, $or:expr) => {
                match $expr {
                    Ok(v) => v,
                    Err(e) => {
                        use MoveIntoRaw;
                        use failure::Error;
                        if let Some(errp) = $errp {
                            let e : Error = e.into();
                            *errp = e.move_into_raw();
                        }
                        return $or;
                    },
                }
            };
        }

        /// Like try! for ffi glue.
        ///
        /// Unwraps the given expression.  On failure, stashes the
        /// error in the context and returns NULL.
        #[allow(unused_macros)]
        macro_rules! ffi_try {
            ($expr:expr) => {
                ffi_try_or!($expr, ::std::ptr::null_mut())
            };
        }

        /// Like try! for ffi glue, then box into raw pointer.
        ///
        /// This is used to transfer ownership from Rust to C.
        ///
        /// Unwraps the given expression.  On success, it boxes the
        /// value and turns it into a raw pointer.  On failure,
        /// stashes the error in the context and returns NULL.
        #[allow(unused_macros)]
        macro_rules! ffi_try_box {
            ($expr:expr) => {
                Box::into_raw(Box::new(ffi_try!($expr)))
            }
        }
    }
}

/// Box, then turn into raw pointer.
///
/// This is used to transfer ownership from Rust to C.
macro_rules! box_raw {
    ($expr:expr) => {
        Box::into_raw(Box::new($expr))
    }
}

/// Box an Option<T>, then turn into raw pointer.
///
/// This is used to transfer ownership from Rust to C.
macro_rules! maybe_box_raw {
    ($expr:expr) => {
        $expr.map(|x| box_raw!(x)).unwrap_or(::std::ptr::null_mut())
    }
}


/* Support for sequoia_ffi_macros::ffi_wrapper_type-based object
 * handling.  */

/// Moves an object from C to Rust, taking ownership.
pub(crate) trait MoveFromRaw<T> {
    /// Moves this object from C to Rust, taking ownership.
    fn move_from_raw(self) -> T;
}

/// Moves a reference to an object from C to Rust.
pub(crate) trait RefRaw<T> {
    /// Moves this reference to an object from C to Rust.
    fn ref_raw(self) -> T;
}

/// Moves a mutable reference to an object from C to Rust.
pub(crate) trait RefMutRaw<T> {
    /// Moves this mutable reference to an object from C to Rust.
    fn ref_mut_raw(self) -> T;
}

/// Moves an object from Rust to C, releasing ownership.
pub(crate) trait MoveIntoRaw<T> {
    /// Moves this object from Rust to C, releasing ownership.
    fn move_into_raw(self) -> T;
}

/// Moves an object from Rust to C, releasing ownership.
pub(crate) trait MoveResultIntoRaw<T> {
    /// Moves this object from Rust to C, releasing ownership.
    fn move_into_raw(self, errp: Option<&mut *mut self::error::Error>) -> T;
}

/// Indicates that a pointer may be NULL.
pub type Maybe<T> = Option<::std::ptr::NonNull<T>>;

/* Hashing support.  */

/// Builds hashers for computing hashes.
///
/// This is used to derive Hasher instances for computing hashes of
/// objects so that they can be used in hash tables by foreign code.
pub(crate) fn build_hasher() -> DefaultHasher {
    lazy_static! {
        static ref RANDOM_STATE: RandomState = RandomState::new();
    }
    RANDOM_STATE.build_hasher()
}

pub mod armor;
pub mod crypto;
pub mod error;
pub mod fingerprint;
pub mod io;
pub mod keyid;
pub mod packet;
pub mod packet_pile;
pub mod parse;
pub mod serialize;
pub mod tpk;
pub mod tsk;
pub mod revocation_status;
