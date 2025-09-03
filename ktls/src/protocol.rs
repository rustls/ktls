//! TLS protocol enums that are not publically exposed by rustls.

#![allow(non_upper_case_globals)]

use std::fmt;

macro_rules! c_enum {
    {
        $( #[$attr:meta] )*
        $vis:vis enum $name:ident: $repr:ty {
            $(
                $( #[$vattr:meta] )*
                $variant:ident = $value:expr
            ),* $(,)?
        }
    } => {
        $( #[$attr] )*
        #[repr(transparent)]
        $vis struct $name($vis $repr);

        impl $name {
            $(
                $( #[$vattr] )*
                $vis const $variant: Self = Self($value);
            )*
        }

        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                $( const $variant: $repr = $name::$variant.0; )*

                let text = match self.0 {
                    $( $variant => concat!(stringify!($name), "::", stringify!($variant)), )*
                    _ => return f.debug_tuple(stringify!($name)).field(&self.0).finish()
                };

                f.write_str(text)
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                $( const $variant: $repr = $name::$variant.0; )*

                let text = match self.0 {
                    $( $variant => stringify!($variant), )*
                    _ => return <$repr as fmt::Display>::fmt(&self.0, f)
                };

                f.write_str(text)
            }
        }

        impl From<$repr> for $name {
            fn from(value: $repr) -> Self {
                Self(value)
            }
        }

        impl From<$name> for $repr {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    }
}

/// `KeyUpdate`, not requested
pub(crate) const KEY_UPDATE_NOT_REQUESTED: u8 = 0;

/// `KeyUpdate`, requested
pub(crate) const KEY_UPDATE_REQUESTED: u8 = 1;

c_enum! {
    #[derive(Copy, Clone, Eq, PartialEq)]
    pub(crate) enum KeyUpdateRequest: u8 {
        UpdateNotRequested = KEY_UPDATE_NOT_REQUESTED,
        UpdateRequested = KEY_UPDATE_REQUESTED
    }
}
