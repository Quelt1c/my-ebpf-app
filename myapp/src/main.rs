use anyhow::{Context, Result};
use aya::maps::AsyncPerfEventArray;
use aya::programs::KProbe;
use aya::util::online_cpus;
use aya::Ebpf;
use bytes::BytesMut;
use myapp_common::NetworkEvent;
use tokio::signal;

#[tokio::main]
async fn main() -> Result<()> {
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/myapp-ebpf"
    ))
    .context("Failed to load eBPF bytecode")?;

    let probes = [
        ("handle_tcp_sendmsg", "tcp_sendmsg"),
        ("handle_udp_sendmsg", "udp_sendmsg"),
        ("handle_udp_recvmsg", "udp_recvmsg"),
    ];

    for (prog_name, fn_name) in probes {
        let program: &mut KProbe = bpf
            .program_mut(prog_name)
            .with_context(|| format!("Program '{}' not found", prog_name))?
            .try_into()
            .context("Failed to convert program to KProbe")?;

        program.load().context("Failed to load kprobe program")?;
        program
            .attach(fn_name, 0)
            .with_context(|| format!("Failed to attach kretprobe to '{}'", fn_name))?;
    }

    let map = bpf.take_map("EVENTS").context("Map 'EVENTS' not found")?;
    let mut events = AsyncPerfEventArray::try_from(map)
        .context("Failed to create AsyncPerfEventArray from map")?;

    println!("Network probes attached!");
    println!(
        "{:<10} | {:<16} | {:<10} | {}",
        "PID", "COMMAND", "ACTION", "BYTES"
    );
    println!("{:-<55}", "");

    let cpus = online_cpus().map_err(|(_, e)| e)?;
    let event_size = std::mem::size_of::<NetworkEvent>();

    for cpu_id in cpus {
        let mut buf = events.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(1024); 10];
            loop {
                if let Ok(events) = buf.read_events(&mut buffers).await {
                    for i in 0..events.read {
                        let buf = &buffers[i];
                        if buf.len() >= event_size {
                            if let Ok(event) =
                                bytemuck::try_pod_read_unaligned::<NetworkEvent>(&buf[..event_size])
                            {
                                let comm_str = std::str::from_utf8(&event.comm)
                                    .unwrap_or("")
                                    .trim_matches('\0');

                                let action = match event.direction {
                                    0 => "TCP SEND",
                                    1 => "UDP SEND",
                                    2 => "UDP RECV",
                                    _ => "UNKNOWN",
                                };

                                println!(
                                    "{:<10} | {:<16} | {:<10} | {} B",
                                    event.pid, comm_str, action, event.bytes
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    signal::ctrl_c().await?;
    println!("\nExiting");
    Ok(())
}
