use std::{ env, fmt };
use std::io::{ self, Write };
use std::process::{ Command, Termination, ExitCode };
use failure::{ Fallible, Error };
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
            return Err(err_msg(format!("File already exists: {}", $path.canonicalize()?.display())));
        }
    };
}

macro_rules! unwrap {
    ( $msg:expr ) => {{
        let crate::core::format::Envelope(_, _, value) = $msg;
        value
    }}
}

pub struct Exit<E>(pub Result<(), E>, pub Stdio);

impl Termination for Exit<Error> {
    fn report(self) -> i32 {
        let Exit(result, mut stdio) = self;

        fn is_backtrace() -> bool {
            match env::var_os("RUST_BACKTRACE") {
                Some(ref v) if v == "0" => false,
                Some(_) => true,
                None => false
            }
        }

        match result {
            Ok(()) => ExitCode::SUCCESS.report(),
            Err(err) => {
                let _ = stdio.eprint(|stderr| -> io::Result<()> {
                    writeln!(stderr, "error:")?;
                    writeln!(stderr, "\t{}", err)?;
                    for cause in err.iter_chain().skip(1) {
                        writeln!(stderr, "\t{}", cause)?;
                    }

                    if is_backtrace() {
                        writeln!(stderr, "{}", err.backtrace())?;
                    }

                    Ok(())
                });

                ExitCode::FAILURE.report()
            }
        }
    }
}


pub fn askpass<F, T>(f: F)
    -> Fallible<T>
    where F: FnOnce(&str) -> Fallible<T>
{
    const PROMPT: &str = "Password:";

    if let Ok(bin) = env::var("ENE_ASKPASS") {
        Command::new(bin)
            .arg(PROMPT)
            .output()
            .map_err(Into::into)
            .and_then(|output| {
                let pw = String::from_utf8(output.stdout)?;
                f(&pw)
            })
    } else {
        ttyaskpass::askpass(PROMPT, f)
    }
}


pub struct Cbor;

impl Serde for Cbor {
    type Error = CborError;

    fn to_vec<T: Serialize>(value: &T) -> Result<Vec<u8>, error::Error<Self::Error>> {
        cbor::to_vec(value).map_err(error::Error::Format)
    }

    fn from_slice<'a, T: Deserialize<'a>>(slice: &'a [u8]) -> Result<T, error::Error<Self::Error>> {
        cbor::from_slice(slice).map_err(error::Error::Format)
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

    #[allow(dead_code)]
    pub fn good(&mut self, args: fmt::Arguments) -> io::Result<()> {
        self.stdout.set_color(ColorSpec::new().set_fg(Some(Color::Green)))?;
        self.stdout.write_fmt(args)?;
        writeln!(self.stdout)?;
        self.stdout.set_color(ColorSpec::new().set_fg(None))?;
        Ok(())
    }

    pub fn info(&mut self, args: fmt::Arguments) -> io::Result<()> {
        self.stdout.set_color(ColorSpec::new().set_fg(None))?;
        self.stdout.write_fmt(args)?;
        writeln!(self.stdout)?;
        Ok(())
    }

    pub fn warn(&mut self, args: fmt::Arguments) -> io::Result<()> {
        self.stderr.set_color(ColorSpec::new().set_fg(Some(Color::Red)))?;
        self.stderr.write_fmt(args)?;
        writeln!(self.stderr)?;
        self.stderr.set_color(ColorSpec::new().set_fg(None))?;
        Ok(())
    }

    pub fn print<E, F>(&mut self, f: F)
        -> Result<(), E>
        where F: FnOnce(&mut StandardStream) -> Result<(), E>,
    {
        f(&mut self.stdout)
    }

    pub fn eprint<E, F>(&mut self, f: F)
        -> Result<(), E>
        where F: FnOnce(&mut StandardStream) -> Result<(), E>,
    {
        f(&mut self.stderr)
    }
}
