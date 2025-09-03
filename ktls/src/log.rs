//! Logger macros.

#[macro_export]
#[doc(hidden)]
macro_rules! trace {
    ($($tt:tt)*) => {
        #[cfg(feature = "tracing")]
        tracing::trace!($($tt)*);

        #[cfg(all(feature = "log", not(feature = "tracing")))]
        log::trace!($($tt)*);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! debug {
    ($($tt:tt)*) => {
        #[cfg(feature = "tracing")]
        tracing::debug!($($tt)*);

        #[cfg(all(feature = "log", not(feature = "tracing")))]
        log::debug!($($tt)*);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! info {
    ($($tt:tt)*) => {
        #[cfg(feature = "tracing")]
        tracing::info!($($tt)*);

        #[cfg(all(feature = "log", not(feature = "tracing")))]
        log::info!($($tt)*);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! warn {
    ($($tt:tt)*) => {
        #[cfg(feature = "tracing")]
        tracing::warn!($($tt)*);

        #[cfg(all(feature = "log", not(feature = "tracing")))]
        log::warn!($($tt)*);
    };
}

#[macro_export]
#[doc(hidden)]
macro_rules! error {
    ($($tt:tt)*) => {
        #[cfg(feature = "tracing")]
        tracing::error!($($tt)*);

        #[cfg(all(feature = "log", not(feature = "tracing")))]
        log::error!($($tt)*);
    };
}
