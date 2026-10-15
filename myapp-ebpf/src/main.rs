#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_comm, bpf_get_current_pid_tgid},
    macros::{kretprobe, map},
    maps::PerfEventArray,
    programs::RetProbeContext,
};
use myapp_common::NetworkEvent;

#[map]
static EVENTS: PerfEventArray<NetworkEvent> = PerfEventArray::new(0);

#[kretprobe]
pub fn handle_tcp_sendmsg(ctx: RetProbeContext) -> u32 {
    let _ = process_net_event(ctx, 0);
    0
}

#[kretprobe]
pub fn handle_tcp_recvmsg(ctx: RetProbeContext) -> u32 {
    let _ = process_net_event(ctx, 1);
    0
}

#[kretprobe]
pub fn handle_udp_sendmsg(ctx: RetProbeContext) -> u32 {
    let _ = process_net_event(ctx, 2);
    0
}

#[kretprobe]
pub fn handle_udp_recvmsg(ctx: RetProbeContext) -> u32 {
    let _ = process_net_event(ctx, 3);
    0
}

fn process_net_event(ctx: RetProbeContext, direction: u8) -> Result<(), u32> {
    let raw_ret: i32 = ctx.ret().unwrap_or(0);

    if raw_ret <= 0 {
        return Ok(());
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 1u32)?;

    let event = NetworkEvent {
        bytes: raw_ret as u64,
        pid,
        direction,
        _padding: [0; 3],
        comm,
    };

    EVENTS.output(&ctx, &event, 0);

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
