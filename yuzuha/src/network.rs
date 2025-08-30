use std::ffi::{CStr, CString};

use yuzuha_codegen::use_offsets;

use crate::{BASE, PtrToStringAnsi, interceptor::Interceptor, util};

#[use_offsets(MAKE_INITIAL_URL, PTR_TO_STRING_ANSI)]
pub fn hook_make_initial_url(interceptor: &mut Interceptor) {
    const SDK_URL: &str = "http://127.0.0.1:20100";
    const DISPATCH_URL: &str = "http://127.0.0.1:10100";

    interceptor.attach(MAKE_INITIAL_URL, |ctx| {
        let url = util::read_csharp_string(ctx.registers().rcx as *const u8);

        let mut new_url = match url.as_str() {
            s if (s.contains("mihoyo.com") || s.contains("hoyoverse.com")) => SDK_URL.to_string(),
            s if (s.contains("globaldp-prod-os01.zenlesszonezero.com")
                || s.contains("globaldp-prod-cn01.juequling.com")) =>
            {
                DISPATCH_URL.to_string()
            }
            s => {
                println!("Leaving request as-is: {s}");
                return;
            }
        };

        url.split('/').skip(3).for_each(|s| {
            new_url.push('/');
            new_url.push_str(s);
        });

        println!("UnityWebRequest: \"{url}\", replacing with \"{new_url}\"");
        let ptr_to_string_ansi = unsafe {
            std::mem::transmute::<usize, PtrToStringAnsi>(BASE.get().unwrap() + PTR_TO_STRING_ANSI)
        };

        ctx.registers().rcx = ptr_to_string_ansi(
            CString::new(new_url.as_str())
                .unwrap()
                .to_bytes_with_nul()
                .as_ptr(),
        );
    });
}

#[use_offsets(WEB_REQUEST_CREATE, PTR_TO_STRING_ANSI)]
pub fn hook_web_request_create(interceptor: &mut Interceptor) {
    interceptor.attach(WEB_REQUEST_CREATE, |ctx| {
        let s = util::read_csharp_string(ctx.registers().rcx as *const u8);
        if s.contains("StandaloneWindows64/cn/") {
            let s = s.replace("StandaloneWindows64/cn/", "StandaloneWindows64/oversea/");
            println!("replaced: {s}");
            let ptr_to_string_ansi = unsafe {
                std::mem::transmute::<usize, PtrToStringAnsi>(
                    BASE.get().unwrap() + PTR_TO_STRING_ANSI,
                )
            };

            ctx.registers().rcx =
                ptr_to_string_ansi(CString::new(s).unwrap().to_bytes_with_nul().as_ptr()) as u64;
        }
    });
}

pub fn block_security_file(interceptor: &mut Interceptor) {
    use windows::Win32::System::LibraryLoader::{GetModuleHandleA, GetProcAddress};
    use windows::core::s;

    let getaddrinfo = unsafe {
        let ws2_32 = GetModuleHandleA(s!("Ws2_32.dll")).unwrap();
        GetProcAddress(ws2_32, s!("getaddrinfo")).unwrap()
    };

    if let Err(err) = interceptor.attach_by_address(getaddrinfo as usize, |ctx| unsafe {
        let host_ptr = ctx.registers().rcx as *const i8;
        let host = CStr::from_ptr(host_ptr).to_string_lossy();

        if host == "globaldp-prod-cn01.juequling.com" {
            println!("potential query_security_file request suppressed");
            std::ptr::copy_nonoverlapping(c"0.0.0.0".as_ptr(), ctx.registers().rcx as *mut i8, 9);
        }
    }) {
        eprintln!("failed to attach to Ws2_32::getaddrinfo, cause: {err}");
    }
}
