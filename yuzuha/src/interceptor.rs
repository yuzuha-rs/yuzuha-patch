use ilhook::{HookError, x64::*};

pub struct Interceptor {
    module_base: usize,
    active_hooks: Vec<HookPoint>,
}

pub struct Context {
    registers: *mut Registers,
}

pub type AttachCallback = fn(ctx: &mut Context);

impl Interceptor {
    pub fn new(base: usize) -> Self {
        Self {
            module_base: base,
            active_hooks: Vec::new(),
        }
    }

    pub fn attach(&mut self, offset: usize, callback: AttachCallback) {
        if let Err(err) = self.attach_by_address(self.module_base + offset, callback) {
            eprintln!("failed to attach to 0x{offset:X}, cause: {err}");
        }
    }

    pub fn attach_by_address(&mut self, address: usize, callback: AttachCallback) -> Result<(), HookError> {
        let hooker = Hooker::new(
            address,
            HookType::JmpBack(attach_callback),
            CallbackOption::None,
            callback as usize,
            HookFlags::empty(),
        );

        unsafe {
            self.active_hooks.push(hooker.hook()?);
        }

        Ok(())
    }
}

impl Context {
    pub fn registers(&mut self) -> &mut Registers {
        unsafe { &mut *self.registers }
    }
}

unsafe extern "win64" fn attach_callback(reg: *mut Registers, actual_callback: usize) {
    let callback = unsafe { std::mem::transmute::<usize, AttachCallback>(actual_callback) };
    callback(&mut Context { registers: reg });
}
