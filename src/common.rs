use std::env;
use std::process::{ Command, Termination, ExitCode };
use failure::Error;
use serde::{ Serialize, Deserialize };
use serde_cbor as cbor;
use serde_cbor::error::Error as CborError;
use crate::core::error;
use crate::core::define::Serde;


macro_rules! info {
    ( $e:expr ) => {
        //
    };
    ( $fmt:expr, $( $args:tt )+ ) => {
        //
    };
}

macro_rules! warn {
    ( $e:expr ) => {
        eprintln!($e)
    };
    ( $fmt:expr, $( $args:tt )+ ) => {
        eprintln!($fmt, $( $args )*)
    };
}

macro_rules! check {
    ( is_file $path:expr ) => {
        if $path.is_file() {
            return Err(err_msg(format!("File already exists: {}", $path.display())));
        }
    };
}

macro_rules! unwrap {
    ( $msg:expr ) => {{
        let crate::core::format::Envelope(_, _, value) = $msg;
        value
    }}
}

pub struct Exit<E>(pub Result<(), E>);

impl Termination for Exit<Error> {
    fn report(self) -> i32 {
        let Exit(result) = self;

        match result {
            Ok(()) => ExitCode::SUCCESS.report(),
            Err(err) => {
                eprintln!("{:?}", err);

                // TODO

                ExitCode::FAILURE.report()
            }
        }
    }
}


pub fn askpass<F, T>(prompt: &str, f: F)
    -> Result<T, Error>
    where F: FnOnce(&str) -> Result<T, Error>
{
    if let Ok(bin) = env::var("ENE_ASKPASS") {
        Command::new(bin)
            .arg(prompt)
            .output()
            .map_err(Into::into)
            .and_then(|output| {
                let pw = String::from_utf8(output.stdout)?;
                f(&pw)
            })
    } else {
        ttyaskpass::askpass(prompt, f)
    }
}


pub struct Cbor;

impl Serde for Cbor {
    type Error = CborError;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, error::Error<Self::Error>> {
        cbor::to_vec(value)
            .map_err(|err| error::Error::Format(err.into()))
    }

    fn from_slice<'a, T: Deserialize<'a>>(slice: &'a [u8]) -> Result<T, error::Error<Self::Error>> {
        cbor::from_slice(slice)
            .map_err(|err| error::Error::Format(err.into()))
    }
}
