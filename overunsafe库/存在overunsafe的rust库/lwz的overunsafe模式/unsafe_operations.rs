// unsafe_operations.rs

use std::ptr;
use std::slice;
use std::mem;
use std::ffi::CString;

// 1. 使用 std::ptr::read_unaligned 读取未对齐的数据
fn use_read_unaligned() {
    let data: [u8; 5] = [0x01, 0x00, 0x00, 0x00, 0x02]; // 模拟未对齐的u32
    let unaligned_ptr = &data[1] as *const u8 as *const u32;
    
    unsafe {
        let value = ptr::read_unaligned(unaligned_ptr); // 使用 unsafe 读取未对齐的数据
        println!("Value from read_unaligned: {}", value);
    }
}

// 2. 使用 std::ptr::write_unaligned 写入未对齐的数据
fn use_write_unaligned() {
    let mut data: [u8; 5] = [0u8; 5];
    let unaligned_ptr = &mut data[1] as *mut u8 as *mut u32;

    unsafe {
        ptr::write_unaligned(unaligned_ptr, 0x12345678); // 使用 unsafe 写入未对齐的数据
        println!("Data after write_unaligned: {:?}", data);
    }
}

// 3. 使用 std::slice::from_raw_parts 创建切片
fn use_from_raw_parts() {
    let data: [u32; 4] = [1, 2, 3, 4];
    let ptr = data.as_ptr();
    
    unsafe {
        let slice = slice::from_raw_parts(ptr, 4); // 使用 unsafe 从裸指针创建切片
        println!("Slice from from_raw_parts: {:?}", slice);
    }
}

// 4. 使用 std::mem::transmute 类型转换
fn use_transmute() {
    let x: u32 = 42;

    unsafe {
        let y: f32 = mem::transmute(x); // 使用 unsafe 进行类型转换
        println!("Value after transmute: {}", y);
    }
}

// 5. 使用 std::mem::zeroed 初始化零值
fn use_zeroed() {
    unsafe {
        let x: u32 = mem::zeroed(); // 使用 unsafe 初始化零值
        println!("Value after zeroed: {}", x);
    }
}

// 6. 使用 std::ptr::write 手动写入数据
fn use_ptr_write() {
    let mut x = 0;
    let ptr = &mut x as *mut i32;

    unsafe {
        ptr::write(ptr, 42); // 使用 unsafe 写入数据
        println!("Value after ptr::write: {}", x);
    }
}

fn main() {
    use_read_unaligned();
    use_write_unaligned();
    use_from_raw_parts();
    use_transmute();
    use_zeroed();
    use_ptr_write();
}
