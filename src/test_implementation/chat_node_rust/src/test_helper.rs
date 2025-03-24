use libp2p::PeerId;
use std::collections::HashMap;
use std::time::SystemTime;

pub struct TestHelper {
    pub have_send_ping: bool,
    pub tests_start_time: SystemTime,
    pub ping_start_time: Vec<SystemTime>,
    pub local_peer_id: PeerId,
    pub time_table: Vec<HashMap<String, u128>>,
    pub ping_size_records: Vec<u32>,
    pub average_time_records: Vec<f64>,
    pub ping_counter: u32,
}

impl TestHelper {
    pub fn new_test_helper(peer_id: PeerId) -> TestHelper {
        TestHelper {
            have_send_ping: false,
            tests_start_time: SystemTime::now(),
            ping_start_time: Vec::new(),
            local_peer_id: peer_id,
            time_table: Vec::new(),
            ping_size_records: Vec::new(),
            average_time_records: Vec::new(),
            ping_counter: 0,
        }
    }

    pub fn clear_data(&mut self) {
        self.have_send_ping = false;
        self.tests_start_time = SystemTime::now();
        self.ping_start_time = Vec::new();
        self.time_table = Vec::new();
        self.ping_size_records = Vec::new();
        self.average_time_records = Vec::new();
        self.ping_counter = 0;
    }

    pub fn start_ping_test(&mut self) {
        self.ping_start_time.push(SystemTime::now());
        self.time_table.push(HashMap::new());
    }

    pub fn append_ping_result(&mut self, peer_id: &String, ping_id: usize) {
        let elapsed = self.ping_start_time[ping_id].elapsed().unwrap().as_millis();

        while self.time_table.len() <= ping_id {
            self.time_table.push(HashMap::new());
        }

        match self.time_table[ping_id].get(&peer_id.clone()) {
            Some(peer_id) => {}
            None => {
                self.time_table[ping_id].insert(peer_id.clone(), elapsed);
            }
        }
    }

    pub fn show_test_results(&mut self) {
        let mut total_average_time = 0f64;
        let mut total_average_ping_size = 0;
        let mut record_number = 0;
        for (i, ping_record) in self.time_table.iter().enumerate() {
            let mut average_time = 0f64;
            for receive_time in ping_record.values() {
                average_time = average_time + (receive_time.clone() as f64);
            }
            average_time = average_time / ping_record.len() as f64;
            average_time = average_time / 2f64;

            if average_time.is_nan() {
                println!("Average time is NaN");
            } else {
                println!(
                    "Average time for ping test {i}: {average_time} ms, where was received {} ping replays",
                    ping_record.len()
                );

                total_average_ping_size += ping_record.len();
                total_average_time += average_time;

                record_number += 1;
            }
        }

        println!(
            "Total average time for ping request: {} ms, while on average, received {} ping replays",
            total_average_time  / record_number as f64,
            total_average_ping_size as f64 / record_number as f64
        );
    }
}
