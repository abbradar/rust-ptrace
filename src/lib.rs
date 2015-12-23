#![feature(step_by)]
extern crate libc;
extern crate posix_ipc as ipc;
#[macro_use]
extern crate bitflags;
#[macro_use]
extern crate enum_primitive;
extern crate num;

use std::ptr;
use std::default::Default;
use std::vec::Vec;
use std::mem;
use std::io;
use libc::{c_long, c_ulong};

use num::FromPrimitive;

#[cfg(target_arch = "x86_64")]
mod regs {
  pub type Address = u64;
  pub type Word = u64;

  #[derive(Copy, Clone, Default, Debug)]
  #[repr(C)]
  pub struct Registers {
    pub r15: Word,
    pub r14: Word,
    pub r13: Word,
    pub r12: Word,
    pub rbp: Word,
    pub rbx: Word,
    pub r11: Word,
    pub r10: Word,
    pub r9: Word,
    pub r8: Word,
    pub rax: Word,
    pub rcx: Word,
    pub rdx: Word,
    pub rsi: Word,
    pub rdi: Word,
    pub orig_rax: Word,
    pub rip: Word,
    pub cs: Word,
    pub eflags: Word,
    pub rsp: Word,
    pub ss: Word,
    pub fs_base: Word,
    pub gs_base: Word,
    pub ds: Word,
    pub es: Word,
    pub fs: Word,
    pub gs: Word
  }
}

#[cfg(target_arch = "x86")]
mod regs {
  pub type Address = u32;
  pub type Word = u32;

  #[derive(Copy, Clone, Default, Debug)]
  #[repr(C)]
  pub struct Registers {
    pub ebx: Word,
    pub ecx: Word,
    pub edx: Word,
    pub esi: Word,
    pub edi: Word,
    pub ebp: Word,
    pub eax: Word,
    pub xds: Word,
    pub xes: Word,
    pub xfs: Word,
    pub xgs: Word,
    pub orig_eax: Word,
    pub eip: Word,
    pub xcs: Word,
    pub eflags: Word,
    pub esp: Word,
    pub xss: Word,
  }
}

pub use regs::*;

#[derive(Copy, Clone)]
pub enum Action {
  Allow,
  Kill
}

#[derive(Debug, Copy, Clone)]
pub enum Request {
  TraceMe = 0,
  PeekText = 1,
  PeekData = 2,
  PeekUser = 3,
  PokeText = 4,
  PokeData = 5,
  PokeUser = 6,
  Continue = 7,
  Kill = 8,
  SingleStep = 9,
  GetRegs = 12,
  SetRegs = 13,
  GetSigInfo = 0x4202,
  SetSigInfo = 0x4203,
  Attach = 16,
  Detatch = 17,
  Syscall = 24,
  SetOptions = 0x4200,
  GetEventMsg = 0x4201,
  Seize = 0x4206,
}

enum_from_primitive! {
#[derive(Copy, Clone, Debug)]
pub enum Event {
  Fork = 1,
  VFork = 2,
  Clone = 3,
  Exec = 4,
  VForkDone = 5,
  Exit = 6,
  Seccomp = 7,
  Stop = 128
}
}

impl Event {
    pub fn from_wait_status(st: i32) -> Option<Event> {
        let e: Option<Event> = Event::from_i32(((st >> 8) & !5) >> 8);
        return e;
    }
}

bitflags! {
  flags Options: u32 {
    const SysGood = 1,
    const TraceFork = 1 << 1,
    const TraceVFork = 1 << 2,
    const TraceClone = 1 << 3,
    const TraceExec = 1 << 4,
    const TraceVForkDone = 1 << 5,
    const TraceExit = 1 << 6,
    const TraceSeccomp = 1 << 7,
    const ExitKill = 1 << 20
  }
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SigInfo {
	pub signo: libc::c_int,
	pub code: libc::c_int,
	pub value: *const libc::c_void,
	pub errno: libc::c_int,
	pub pid: libc::pid_t,
	pub uid: libc::uid_t,
	pub addr: *const libc::c_void,
	pub status: libc::c_int,
	pub band: libc::c_int,
}

impl Default for SigInfo {
  fn default() -> SigInfo {
    SigInfo {
      signo: 0,
      code: 0,
      value: ptr::null(),
      errno: 0,
      pid: 0,
      uid: 0,
      addr: ptr::null(),
      status: 0,
      band: 0,
    }
  }
}

pub fn setoptions(pid: libc::pid_t, opts: Options) -> Result<(), io::Error> {
  unsafe {
    raw (Request::SetOptions, pid, ptr::null_mut(), opts.bits as *mut libc::c_void)
      .map(|c| assert!(c == 0))
  }
}

pub fn getregs(pid: libc::pid_t) -> Result<Registers, io::Error> {
  let mut buf: Registers = Default::default();
  let buf_mut: *mut Registers = &mut buf;

  unsafe {
    raw (Request::GetRegs, pid, ptr::null_mut(), buf_mut as *mut libc::c_void)
      .map(|c| { assert!(c == 0); buf })
  }
}

pub fn setregs(pid: libc::pid_t, regs: &Registers) -> Result<(), io::Error> {
    unsafe {
        let buf: *mut libc::c_void = mem::transmute(regs);
        raw (Request::SetRegs, pid, ptr::null_mut(), buf)
            .map(|c| assert!(c == 0))
    }
}

pub fn getsiginfo(pid: libc::pid_t) -> Result<SigInfo, io::Error> {
  let mut buf: SigInfo = Default::default();
  let buf_mut: *mut SigInfo = &mut buf;

  unsafe {
    raw (Request::GetSigInfo, pid, ptr::null_mut(), buf_mut as *mut libc::c_void)
      .map(|c| { assert!(c == 0); buf })
  }
}

pub fn setsiginfo(pid: libc::pid_t, siginfo: &SigInfo) -> Result<(), io::Error> {
    unsafe {
        let buf: *mut libc::c_void = mem::transmute(siginfo);
        raw (Request::SetSigInfo, pid, ptr::null_mut(), buf)
            .map(|c| assert!(c == 0))
    }
}

pub fn seize(pid: libc::pid_t) -> Result<(), io::Error> {
    unsafe {
        raw (Request::Seize, pid, ptr::null_mut(), ptr::null_mut())
          .map(|c| assert!(c == 0))
    }
}

pub fn attach(pid: libc::pid_t) -> Result<(), io::Error> {
    unsafe {
        raw (Request::Attach, pid, ptr::null_mut(), ptr::null_mut())
        .map(|c| assert!(c == 0))
    }
}

pub fn release(pid: libc::pid_t, signal: ipc::signals::Signal) -> Result<(), io::Error> {
  unsafe {
    raw (Request::Detatch, pid, ptr::null_mut(), (signal as u32) as *mut libc::c_void)
        .map(|c| assert!(c == 0))
  }
}

pub fn cont(pid: libc::pid_t, signal: ipc::signals::Signal) -> Result<(), io::Error> {
  unsafe {
    raw (Request::Continue, pid, ptr::null_mut(), (signal as u32) as *mut libc::c_void)
        .map(|c| assert!(c == 0))
  }
}

pub fn syscall(pid: libc::pid_t, signal: ipc::signals::Signal) -> Result<(), io::Error> {
  unsafe {
    raw (Request::Syscall, pid, ptr::null_mut(), (signal as u32) as *mut libc::c_void)
        .map(|c| assert!(c == 0))
  }
}

pub fn traceme() -> Result<(), io::Error> {
  unsafe {
    raw (Request::TraceMe, 0, ptr::null_mut(), ptr::null_mut()).map(|c| assert!(c == 0))
  }
}

pub fn geteventmsg(pid: libc::pid_t) -> Result<c_long, io::Error> {
  unsafe {
    let mut val: c_long = 0;
    raw (Request::GetEventMsg, pid, ptr::null_mut(), (&mut val as *mut c_long) as *mut libc::c_void).map(|c| { assert!(c == 0); val })
  }
}

unsafe fn raw(request: Request,
       pid: libc::pid_t,
       addr: *mut libc::c_void,
       data: *mut libc::c_void) -> Result<c_long, io::Error> {
  let v = ptrace (request as libc::c_int, pid, addr, data);
  match v {
      -1 => Result::Err(io::Error::last_os_error()),
      _ => Result::Ok(v)
  }
}

extern {
  fn ptrace(request: libc::c_int,
            pid: libc::pid_t,
            addr: *mut libc::c_void,
            data: *mut libc::c_void) -> c_long;
}

#[derive(Copy, Clone, Debug)]
pub struct Syscall {
  pub args: [Word; 6],
  pub call: u64,
  pub pid: libc::pid_t,
  pub return_val: Word
}

impl Syscall {
  pub fn from_pid(pid: libc::pid_t) -> Result<Syscall, io::Error> {
    match getregs (pid) {
        Ok(regs) =>
            Ok(Syscall {
              pid: pid,
              call: regs.orig_rax,
              args: [regs.rdi, regs.rsi, regs.rdx, regs.rcx, regs.r8, regs.r9],
              return_val: regs.rax,
            }),
        Err(e) => Err(e)
    }
  }

  pub fn write(&self) -> Result<(), io::Error> {
      match getregs(self.pid) {
          Ok(mut regs) => {
              regs.rdi = self.args[0];
              regs.rsi = self.args[1];
              regs.rdx = self.args[2];
              regs.rcx = self.args[3];
              regs.r8 = self.args[4];
              regs.r9 = self.args[5];
              regs.orig_rax = self.call;
              regs.rax = self.return_val;
              setregs(self.pid, &regs)
          },
          Err(e) => Err(e)
      }
  }
}

#[derive(Copy, Clone)]
pub struct Reader {
  pub pid: libc::pid_t
}

#[derive(Copy, Clone)]
pub struct Writer {
    pub pid: libc::pid_t
}

impl Writer {
    pub fn new(pid: libc::pid_t) -> Self {
        Writer {
            pid: pid
        }
    }

    pub fn poke_data(&self, address: Address, data: c_ulong) -> Result<(), io::Error> {
        unsafe {
            raw (Request::PokeData, self.pid, address as *mut libc::c_void, data as *mut libc::c_void)
                .map(|c| assert!(c == 0))
        }
    }

    pub fn write_object<T: Sized>(&self, address: Address, data: &T) -> Result<(), io::Error> {
        unsafe {
            let ptr = mem::transmute(data as *const T);
            self.write_ptr(address, ptr, mem::size_of::<T>())
        }
    }

    pub fn write_data(&self, address: Address, buf: &Vec<u8>) -> Result<(), io::Error> {
        unsafe {
            let ptr = buf[..].as_ptr();
            self.write_ptr(address, ptr, buf.len())
        }
    }

    unsafe fn write_ptr(&self, address: Address, ptr: *const u8, size: usize) -> Result<(), io::Error> {
        // The end of our range
        let max_addr = address + size as Address;
        // The last word we can completely overwrite
        let diff = max_addr % mem::size_of::<Word>() as Address;
        let align_end = max_addr - diff;
        for write_addr in (address..align_end).step_by(mem::size_of::<Word>() as Address) {
            let mut d: Word = 0;
            let buf_idx = (write_addr - address) as isize;
            for word_idx in 0..mem::size_of::<Word>() {
                d = set_byte(d, word_idx, *ptr.offset(buf_idx + word_idx as isize));
            }
            try!(self.poke_data(write_addr, d));
        }
        // Handle a partial word overwrite
        if diff != 0 {
            let r = Reader::new(self.pid);
            let mut d = try!(r.peek_data(align_end));
            let buf_idx = align_end as isize;
            for word_idx in 0..diff as usize {
                d = set_byte(d, word_idx, *ptr.offset(buf_idx + word_idx as isize));
            }
            try!(self.poke_data(align_end, d));
        }
        Ok(())
    }
}

impl Reader {
    pub fn new(pid: libc::pid_t) -> Reader {
      Reader {
        pid: pid
      }
    }

    pub fn peek_data(&self, address: Address) -> Result<c_ulong, io::Error> {
        unsafe {
            extern { fn __errno_location() -> *mut libc::c_int; };
            let errno = __errno_location();
            *errno = 0;
            let l = ptrace(Request::PeekData as libc::c_int, self.pid, address as *mut libc::c_void, ptr::null_mut());
            if *errno == 0 {
                Result::Ok(l as c_ulong)
            } else {
                Result::Err(io::Error::last_os_error())
            }
        }
    }

    pub fn read_string(&self, address: Address) -> Result<Vec<u8>, io::Error> {
        let mut buf: Vec<u8> = Vec::with_capacity(1024);
        for read_addr in (address..).step_by(mem::size_of::<c_long>() as Address) {
            let d = try!(self.peek_data(read_addr));
            for word_idx in 0..mem::size_of::<c_long>() {
                let chr = get_byte(d, word_idx);
                if chr == 0 {
                    break;
                }
                buf.push (chr);
            }
        }
        return Ok(buf);
    }

    pub unsafe fn read_object<T: Clone>(&self, address: Address) -> Result<T, io::Error> {
        let buf = try!(self.read_data(address, mem::size_of::<T>()));
        let obj = {
          let ptr : *const T = mem::transmute(buf[..].as_ptr());
          (*ptr).clone()
        };
        Ok(obj)
    }

    pub fn read_data(&self, address: Address, size: usize) -> Result<Vec<u8>, io::Error> {
        let mut buf: Vec<u8> = Vec::with_capacity(size);
        let max_addr = address + size as Address;
        let diff = max_addr % mem::size_of::<c_long>() as Address;
        let align_end = max_addr - diff;
        for read_addr in (address..align_end).step_by(mem::size_of::<c_long>() as Address) {
            let d = try!(self.peek_data(read_addr));
            for word_idx in 0..mem::size_of::<c_long>() {
                let chr = get_byte(d, word_idx);
                buf.push(chr);
            }
        }
        if diff != 0 {
            let d = try!(self.peek_data(align_end));
            for word_idx in 0..diff as usize {
                let chr = get_byte(d, word_idx);
                buf.push(chr);
            }
        }
        return Ok(buf);
    }
}

fn get_byte(d: c_ulong, byte_idx: usize) -> u8 {
    assert!(byte_idx < mem::size_of::<c_ulong>());
    ((d >> (byte_idx * 8)) & 0xff) as u8
}

fn set_byte(d: c_ulong, byte_idx: usize, value: u8) -> c_ulong {
    assert!(byte_idx < mem::size_of::<c_ulong>());
    let shift = byte_idx * 8;
    let mask = 0xff << shift;
    (d & !mask) | (((value as c_ulong) << shift) & mask)
}

#[test]
pub fn test_set_byte() {
    assert_eq!(set_byte(0, 0, 0), 0);
    assert_eq!(set_byte(0xffffffffffff, 0, 0xff), 0xffffffffffff);
    assert_eq!(set_byte(0xffffffffffff, 0, 0),    0xffffffffff00);
    assert_eq!(set_byte(0xffffffffffff, 0, 0xaa), 0xffffffffffaa);
    assert_eq!(set_byte(0xffffffffffff, 1, 0x00), 0xffffffff00ff);
    assert_eq!(set_byte(0xffffffffffff, 4, 0xaa), 0xffaaffffffff);
}

#[test]
pub fn test_get_byte() {
    assert_eq!(get_byte(0, 0), 0);
    assert_eq!(get_byte(!0, 0), 0xff);
    assert_eq!(get_byte(!0, mem::size_of::<Word>()-1), 0xff);
    assert_eq!(get_byte(0xffffffffffaa, 0), 0xaa);
    assert_eq!(get_byte(0x0123456789ab, 1), 0x89);
    assert_eq!(get_byte(0x0123456789ab, 4), 0x23);
}

#[test]
#[should_panic]
pub fn test_set_byte_panic() {
    set_byte(!0, mem::size_of::<Word>(), 0xff);
}
#[test]
#[should_panic]
pub fn test_get_byte_panic() {
    get_byte(!0, mem::size_of::<Word>());
}
