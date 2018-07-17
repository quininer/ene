use failure::Error;
use directories::ProjectDirs;
use crate::opts::SendTo;


impl SendTo {
    pub fn exec(self, dir: &ProjectDirs) -> Result<(), Error> {
        unimplemented!()
    }
}
