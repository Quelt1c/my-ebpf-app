use anyhow::{Context, Result};
use aya::maps::AsyncPerfEventArray;
// use aya::programs::KProbe;
use aya::programs::{FExit, TracePoint};
use aya::util::online_cpus;
use aya::{Btf, Ebpf};
use bytes::BytesMut;
use myapp_common::{NetworkEvent, ProcessEvent};
use tokio::signal;

async fn run() -> Result<()> {
    let mut bpf = Ebpf::load(aya::include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/myapp-ebpf"
    ))
    .context("Failed to load eBPF bytecode")?;

    // let probes = [
    //     ("handle_tcp_sendmsg", "tcp_sendmsg"),
    //     ("handle_udp_sendmsg", "udp_sendmsg"),
    //     ("handle_udp_recvmsg", "udp_recvmsg"),
    //     ("handle_tcp_recvmsg", "tcp_recvmsg"),
    // ];
    //
    // for (prog_name, fn_name) in probes {
    //     let program: &mut KProbe = bpf
    //         .program_mut(prog_name)
    //         .with_context(|| format!("Program '{}' not found", prog_name))?
    //         .try_into()
    //         .context("Failed to convert program to KProbe")?;
    //
    //     program.load().context("Failed to load kprobe program")?;
    //     program
    //         .attach(fn_name, 0)
    //         .with_context(|| format!("Failed to attach kretprobe to '{}'", fn_name))?;
    // }

    let btf = Btf::from_sys_fs().context("Failed to read kernel BTF")?;

    let net_probes = [
        ("tcp_sendmsg_exit", "tcp_sendmsg"),
        ("udp_sendmsg_exit", "udp_sendmsg"),
        ("udp_recvmsg_exit", "udp_recvmsg"),
        ("tcp_recvmsg_exit", "tcp_recvmsg"),
    ];

    for (prog_name, fn_name) in net_probes {
        let program: &mut FExit = bpf
            .program_mut(prog_name)
            .with_context(|| format!("Program '{}' not found", prog_name))?
            .try_into()
            .context("Failed to convert program to FExit")?;

        program
            .load(fn_name, &btf)
            .context("Failed to load fexit program")?;
        program.attach().context("Failed to attach fexit")?;
    }

    let proc_probes = [
        ("handle_exec", "sched", "sched_process_exec"),
        ("handle_exit", "sched", "sched_process_exit"),
    ];

    for (prog_name, category, event) in proc_probes {
        let program: &mut TracePoint = bpf
            .program_mut(prog_name)
            .with_context(|| format!("Program '{}' not found", prog_name))?
            .try_into()
            .context("Failed to convert program to TracePoint")?;

        program
            .load()
            .context("Failed to load tracepoint program")?;
        program
            .attach(category, event)
            .context("Failed to attach tracepoint")?;
    }

    let net_map = bpf
        .take_map("NET_EVENTS")
        .context("Map 'NET_EVENTS' not found")?;
    let mut net_events = AsyncPerfEventArray::try_from(net_map)?;

    let proc_map = bpf
        .take_map("PROC_EVENTS")
        .context("Map 'PROC_EVENTS' not found")?;
    let mut proc_events = AsyncPerfEventArray::try_from(proc_map)?;

    println!("All probes attached successfully!");
    println!("{:-<75}", "");
    println!(
        "{:<10} | {:<16} | {:<12} | {}",
        "PID", "COMMAND", "TYPE", "DETAILS"
    );
    println!("{:-<75}", "");

    let cpus = online_cpus().map_err(|(_, e)| e)?;

    for cpu_id in cpus {
        let mut net_buf = net_events.open(cpu_id, None)?;
        let mut proc_buf = proc_events.open(cpu_id, None)?;

        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(1024); 10];
            let size = std::mem::size_of::<NetworkEvent>();
            loop {
                if let Ok(events) = net_buf.read_events(&mut buffers).await {
                    for i in 0..events.read {
                        if buffers[i].len() >= size {
                            if let Ok(event) = bytemuck::try_pod_read_unaligned::<NetworkEvent>(
                                &buffers[i][..size],
                            ) {
                                let comm = std::str::from_utf8(&event.comm)
                                    .unwrap_or("")
                                    .trim_matches('\0');
                                let action = match event.direction {
                                    0 => "TCP SEND",
                                    1 => "TCP RECV",
                                    2 => "UDP SEND",
                                    3 => "UDP RECV",
                                    _ => "UNKNOWN",
                                };
                                println!(
                                    "{:<10} | {:<16} | {:<12} | {} B",
                                    event.pid, comm, action, event.bytes
                                );
                            }
                        }
                    }
                }
            }
        });

        tokio::spawn(async move {
            let mut buffers = vec![BytesMut::with_capacity(1024); 10];
            let size = std::mem::size_of::<ProcessEvent>();
            loop {
                if let Ok(events) = proc_buf.read_events(&mut buffers).await {
                    for i in 0..events.read {
                        if buffers[i].len() >= size {
                            if let Ok(event) = bytemuck::try_pod_read_unaligned::<ProcessEvent>(
                                &buffers[i][..size],
                            ) {
                                let comm = std::str::from_utf8(&event.comm)
                                    .unwrap_or("")
                                    .trim_matches('\0');
                                let event_action = match event.event_type {
                                    0 => "START",
                                    1 => "EXIT",
                                    _ => "UNKNOWN",
                                };
                                println!(
                                    "{:<10} | {:<16} | {:<12} | UID: {}",
                                    event.pid, comm, event_action, event.uid
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    signal::ctrl_c().await?;
    Ok(())
}

#[tokio::main]
async fn main() {
    match run().await {
        Ok(()) => println!("\nApplication stopped gracefully."),
        Err(err) => {
            eprintln!("\nApplication terminated with error: {:#}", err);
            std::process::exit(1);
        }
    }
}
