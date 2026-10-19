#![no_std]

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct NetworkEvent {
    pub bytes: u64,
    pub pid: u32,
    pub direction: u8,
    pub _padding: [u8; 3],
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for NetworkEvent {}

#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
pub struct ProcessEvent {
    pub pid: u32,
    pub uid: u32,
    pub event_type: u8,
    pub _padding: [u8; 3],
    pub comm: [u8; 16],
}

#[cfg(feature = "user")]
unsafe impl aya::Pod for ProcessEvent {}
