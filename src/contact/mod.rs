pub mod db;

use failure::Error;
use directories::ProjectDirs;
use crate::opts::Contact;


impl Contact {
    pub fn exec(self, dir: &ProjectDirs) -> Result<(), Error> {
        let db_path = dir.data_local_dir().join("ene.sled");

        unimplemented!()
    }
}
