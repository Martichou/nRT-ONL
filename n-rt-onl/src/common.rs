use fastping_rs::Pinger;

pub(crate) fn start_pinger(targets: Vec<String>, icmp_interval: Option<u64>) {
    tokio::spawn(async move {
        let (pinger, results) = match Pinger::new(icmp_interval, Some(32)) {
            Ok((pinger, results)) => (pinger, results),
            Err(e) => panic!("Error creating pinger: {}", e),
        };

        for t in targets {
            pinger.add_ipaddr(&t);
        }

        pinger.run_pinger();

        while results.recv().is_ok() {}
    });
}
