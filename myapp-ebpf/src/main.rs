#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{
        bpf_get_current_comm, bpf_get_current_pid_tgid, bpf_get_current_uid_gid,
        gen::bpf_get_func_ret,
    },
    macros::{fexit, map, tracepoint},
    maps::PerfEventArray,
    programs::{FExitContext, TracePointContext},
    EbpfContext,
};
use myapp_common::{NetworkEvent, ProcessEvent};

#[map]
static NET_EVENTS: PerfEventArray<NetworkEvent> = PerfEventArray::new(0);

#[map]
static PROC_EVENTS: PerfEventArray<ProcessEvent> = PerfEventArray::new(0);

// #[kretprobe]
// pub fn handle_tcp_sendmsg(ctx: RetProbeContext) -> u32 {
//     let _ = process_net_event(ctx, 0);
//     0
// }
//
// #[kretprobe]
// pub fn handle_tcp_recvmsg(ctx: RetProbeContext) -> u32 {
//     let _ = process_net_event(ctx, 1);
//     0
// }
//
// #[kretprobe]
// pub fn handle_udp_sendmsg(ctx: RetProbeContext) -> u32 {
//     let _ = process_net_event(ctx, 2);
//     0
// }
//
// #[kretprobe]
// pub fn handle_udp_recvmsg(ctx: RetProbeContext) -> u32 {
//     let _ = process_net_event(ctx, 3);
//     0
// }
//
// fn process_net_event(ctx: RetProbeContext, direction: u8) -> Result<(), u32> {
//     let raw_ret: i32 = ctx.ret().unwrap_or(0);
//
//     if raw_ret <= 0 {
//         return Ok(());
//     }
//
//     let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
//     let comm = bpf_get_current_comm().map_err(|_| 1u32)?;
//
//     let event = NetworkEvent {
//         bytes: raw_ret as u64,
//         pid,
//         direction,
//         _padding: [0; 3],
//         comm,
//     };
//
//     EVENTS.output(&ctx, &event, 0);
//
//     Ok(())
// }

#[fexit(function = "tcp_sendmsg")]
pub fn tcp_sendmsg_exit(ctx: FExitContext) -> i32 {
    let _ = process_fexit_event(&ctx, 0);
    0
}

#[fexit(function = "tcp_recvmsg")]
pub fn tcp_recvmsg_exit(ctx: FExitContext) -> i32 {
    let _ = process_fexit_event(&ctx, 1);
    0
}

#[fexit(function = "udp_sendmsg")]
pub fn udp_sendmsg_exit(ctx: FExitContext) -> i32 {
    let _ = process_fexit_event(&ctx, 2);
    0
}

#[fexit(function = "udp_recvmsg")]
pub fn udp_recvmsg_exit(ctx: FExitContext) -> i32 {
    let _ = process_fexit_event(&ctx, 3);
    0
}

#[inline(always)]
fn process_fexit_event(ctx: &FExitContext, direction: u8) -> Result<(), u32> {
    let mut ret: u64 = 0;
    if unsafe { bpf_get_func_ret(ctx.as_ptr(), &mut ret) } != 0 {
        return Err(1);
    }

    let ret = ret as i32;
    if ret <= 0 {
        return Ok(());
    }

    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let comm = bpf_get_current_comm().map_err(|_| 2u32)?;

    let event = NetworkEvent {
        bytes: ret as u64,
        pid,
        direction,
        _padding: [0; 3],
        comm,
    };

    NET_EVENTS.output(ctx, &event, 0);

    Ok(())
}

#[tracepoint]
pub fn handle_exec(ctx: TracePointContext) -> u32 {
    let _ = process_proc_event(&ctx, 0);
    0
}

#[tracepoint]
pub fn handle_exit(ctx: TracePointContext) -> u32 {
    let _ = process_proc_event(&ctx, 1);
    0
}

#[inline(always)]
fn process_proc_event(ctx: &TracePointContext, event_type: u8) -> Result<(), u32> {
    let pid = (bpf_get_current_pid_tgid() >> 32) as u32;
    let uid = bpf_get_current_uid_gid() as u32;
    let comm = bpf_get_current_comm().map_err(|_| 3u32)?;

    let event = ProcessEvent {
        pid,
        event_type,
        _padding: [0; 3],
        comm,
        uid,
    };

    PROC_EVENTS.output(ctx, &event, 0);

    Ok(())
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
