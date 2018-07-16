use std::fs;
use std::mem::ManuallyDrop;
use std::path::{ Path, PathBuf };
use failure::{ Error, err_msg };
use serde_cbor as cbor;
use sled::{ ConfigBuilder, Tree, Iter };
use crate::core::key;


pub struct Db {
    tree: ManuallyDrop<Tree>,
    lock: Option<PathBuf>
}

macro_rules! check_lock {
    ( $path:expr ) => {
        if $path.exists() {
            return Err(err_msg(format!("lock exist: {}", $path.display())));
        }
    }
}

impl Db {
    pub fn new(path: &Path) -> Result<Db, Error> {
        let config = ConfigBuilder::new()
            .path(path)
            .build();

        let lock_path = path.with_extension(".read.lock");
        check_lock!(lock_path);

        let lock_path = path.with_extension(".lock");
        check_lock!(lock_path);

        fs::File::create(&lock_path)?;

        Ok(Db {
            tree: ManuallyDrop::new(Tree::start(config)?),
            lock: Some(lock_path)
        })
    }

    pub fn read_only(path: &Path) -> Result<Db, Error> {
        let config = ConfigBuilder::new()
            .path(path)
            .read_only(true)
            .build();

        let lock_path = path.with_extension(".lock");
        check_lock!(lock_path);

        let lock_path = path.with_extension(".read.lock");
        let lock_path = fs::File::create(&lock_path).ok()
            .map(|_| lock_path);

        Ok(Db {
            tree: ManuallyDrop::new(Tree::start(config)?),
            lock: lock_path
        })
    }

    pub fn get(&self, id: &str) -> Result<Option<key::PublicKey>, Error> {
        if let Some(value) = self.tree.get(id.as_bytes())? {
            Ok(Some(cbor::from_slice(&value)?))
        } else {
            Ok(None)
        }
    }

    pub fn set(&self, id: &str, pk: &key::PublicKey) -> Result<(), Error> {
        let id = id.to_string().into_bytes();
        let pk = cbor::to_vec(pk)?;

        self.tree.set(id, pk).map_err(Into::into)
    }

    pub fn filter(&'a self, start: &'a str) -> Filter<'a> {
        let iter = self.tree.iter();
        Filter { iter, start }
    }
}

pub struct Filter<'a> {
    iter: Iter<'a>,
    start: &'a str
}

impl<'a> Iterator for Filter<'a> {
    type Item = Result<(String, key::PublicKey), Error>;

    fn next(&mut self) -> Option<Self::Item> {
        macro_rules! try_some {
            ( $e:expr ) => {
                match $e {
                    Ok(e) => e,
                    Err(err) => return Some(Err(err.into()))
                }
            }
        }

        let (id, value) = try_some!(self.iter.next()?);
        let id = try_some!(String::from_utf8(id));
        if id.starts_with(self.start) {
            let pk = try_some!(cbor::from_slice(&value));
            Some(Ok((id, pk)))
        } else {
            self.next()
        }
    }
}

impl Drop for Db {
    fn drop(&mut self) {
        unsafe {
            ManuallyDrop::drop(&mut self.tree);
        }

        if let Some(ref lock_path) = self.lock {
            let _ = fs::remove_file(lock_path);
        }
    }
}
