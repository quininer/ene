use std::{ env, fmt };
use std::io::{ self, Write };
use std::process::{ Command, Termination, ExitCode };
use failure::Error;
use serde::{ Serialize, Deserialize };
use serde_cbor as cbor;
use serde_cbor::error::Error as CborError;
use termcolor::{ StandardStream, ColorChoice, ColorSpec, Color, WriteColor };
use crate::core::error;
use crate::core::define::Serde;
use crate::opts::ColorChoice as ColorChoice2;


macro_rules! check {
    ( is_file $path:expr ) => {
        if $path.is_file() {
            return Err(err_msg(format!("File already exists: {}", $path.display())));
        }
    };
    ( pk ( $log:expr, $fmt:expr ) : $( $pk:expr, $pack_pk:expr );* ; ) => {
        $(
            if let (Some(pk), Some(pack_pk)) = (&$pk, &$pack_pk) {
                if pk != pack_pk {
                    $log.warn(format_args!($fmt, pk, pack_pk))?;
                }
            }
        )*
    }
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

impl Into<ColorChoice> for ColorChoice2 {
    fn into(self) -> ColorChoice {
        match self {
            ColorChoice2::Always => ColorChoice::Always,
            ColorChoice2::AlwaysAnsi => ColorChoice::AlwaysAnsi,
            ColorChoice2::Auto => ColorChoice::Auto,
            ColorChoice2::Never => ColorChoice::Never
        }
    }
}

pub struct Stdio {
    pub stdout: StandardStream,
    pub stderr: StandardStream
}

impl Stdio {
    pub fn new(choice: ColorChoice) -> Stdio {
        Stdio {
            stdout: StandardStream::stdout(choice),
            stderr: StandardStream::stderr(choice)
        }
    }

    pub fn info(&mut self, args: fmt::Arguments) -> io::Result<()> {
        self.stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
        self.stdout.write_fmt(args)?;
        self.stdout.set_color(ColorSpec::new().set_fg(None))?;
        Ok(())
    }

    pub fn warn(&mut self, args: fmt::Arguments) -> io::Result<()> {
        self.stderr.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
        self.stderr.write_fmt(args)?;
        self.stderr.set_color(ColorSpec::new().set_fg(None))?;
        Ok(())
    }

    pub fn print<E, F>(&mut self, f: F)
        -> Result<(), E>
        where
            F: FnOnce(&mut StandardStream) -> Result<(), E>,
            E: From<io::Error>
    {
        f(&mut self.stdout)
    }
}
