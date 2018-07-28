//! fork from assert_cmd

use std::path::PathBuf;
use failure::{ Error, err_msg };
use escargot::CargoBuild;


#[allow(dead_code)]
pub fn main(args: &[&str]) -> Result<PathBuf, Error> {
    let mut build = CargoBuild::new();

    for a in args {
        build = build.arg(a);
    }

    let bins: Vec<_> = build
        .current_release()
        .exec()?
        .filter_map(|m| extract_filenames(&m, "bin"))
        .collect();
    if bins.is_empty() {
        return Err(err_msg("No binaries in crate"));
    } else if bins.len() != 1 {
        return Err(err_msg(format!(
            "Ambiguous which binary is intended: {:?}",
            bins
        )));
    }
    Ok(bins.into_iter().next().expect("already validated"))
}

pub fn example(name: &str) -> Result<PathBuf, Error> {
    let bins = CargoBuild::new()
        .example(name)
        .current_release()
        .exec()?
        .filter_map(|m| extract_filenames(&m, "example"))
        .collect::<Vec<_>>();

    assert_eq!(bins.len(), 1);
    Ok(bins.into_iter().next().expect("already validated"))
}


#[derive(Deserialize)]
struct MessageTarget<'a> {
    #[serde(borrow)]
    crate_types: Vec<&'a str>,
    #[serde(borrow)]
    kind: Vec<&'a str>,
}

#[derive(Deserialize)]
struct MessageFilter<'a> {
    #[serde(borrow)]
    reason: &'a str,
    target: MessageTarget<'a>,
    filenames: Vec<PathBuf>,
}

fn extract_filenames(msg: &escargot::Message, kind: &str) -> Option<PathBuf> {
    let filter: MessageFilter = msg.convert().ok()?;
    if filter.reason != "compiler-artifact"
        || filter.target.crate_types != ["bin"]
        || filter.target.kind != [kind]
    {
        None
    } else {
        Some(
            filter
                .filenames
                .into_iter()
                .next()
                .expect("files must exist"),
        )
    }
}
