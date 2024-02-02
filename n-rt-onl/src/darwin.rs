use tokio::sync::mpsc::Receiver;

use crate::{Onl, State};

impl Onl {
    /// Start the outage notification process.
    /// Returning the receiver of a MPSC channel.
    pub fn start(mut self) -> Result<Receiver<State>, anyhow::Error> {
        unimplemented!()
    }
}
