use std::collections::{HashMap, VecDeque};

static ACK_CAPACITY: usize = 1000;

#[derive(Debug)]
pub struct AckStore {
    acks: VecDeque<u32>,
    acks_map: HashMap<u32, bool>,
}

impl AckStore {
    pub fn new() -> Self {
        AckStore {
            acks: VecDeque::with_capacity(ACK_CAPACITY),
            acks_map: HashMap::with_capacity(ACK_CAPACITY),
        }
    }

    pub fn add_ack(&mut self, ack: u32) {
        if self.acks.len() >= ACK_CAPACITY {
            if let Some(rack) = self.acks.pop_front() {
                self.acks_map.remove(&rack);
            }
        }
        self.acks.push_back(ack);
        self.acks_map.insert(ack, true);
    }

    pub fn remove_ack(&mut self, ack: u32) {
        self.acks_map.insert(ack, false);
    }
}
