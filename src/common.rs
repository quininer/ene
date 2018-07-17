use std::env;
use std::process::{ Command, Termination, ExitCode };
use failure::Error;


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
