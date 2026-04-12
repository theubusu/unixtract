use binrw::BinRead;

pub static FILE_KEY: [u8; 16] = [
        0x2A, 0x54, 0xA5, 0x30, 0xE0, 0x09, 0xA3, 0xDC,
        0x03, 0xFB, 0xC3, 0x5E, 0x23, 0xA2, 0xC1, 0x0D,
];

pub static FILE_IV: [u8; 16] = [0x00; 16];

// u-boot-2011.06/include/aimage.h
// (C) Copyright 2004-2008 Andre McCurdy, NXP Semiconductors

#[derive(Debug, BinRead)]
pub struct AImageHeader {
    _vector: u32,                       // reserved for a branch instruction (if data_start_offset and data_entry_point_offset are 0)
    _vector2: u32,                      // reserved for a branch instruction branch delay slot
    _magic: u32,                        // 0x41676d69
    _magic2: u32,                       // 0x43634d52
    _release_id: u32,                   // toplevel build / release version
    _platform_id: u32,                  // target platform information
    pub image_type: u32,                // image type
    pub lenght: u32,                    // length of entire image (header + data + trailing padding) 
    _data_lenght: u32,                  // length of image data (ie from data_start_offset to start of trailing padding)
    pub data_start_offset: u32,         // 0 if header is part of data, sizeof(aimage_v1_header_t) if header is prepended to data
    _data_link_address: u32,            // for non-pic executable images, where should the image placed in memory in order to execute
    _data_entry_point_offset: u32,      // 0 if execution entry point is at the beginning of image data
    pub flags: u32,                     // image flags
    _build_time: u32,                   // if non-zero, gives time when image was created (seconds since 1970)
    _build_host_offset: u32,            // if non-zero, offset of a string in the image data giving build host information
    _signature: [u8; 128],              // 32 32bit words == 1024 bit RSA signature
    _hash: [u8; 20],                    // raw sha1 hash (fallback if not checking signature)
    _usd: u32,                          // "un-signed data" (treated as 0 during hash and signature verification, regardless of actual value)
    _reserved: [u8; 28],                // image type specific params etc (number tweaked to keep header size == 256 bytes)
    /*
        Note: The final 16 bytes of the header are used to form the
              IV for aimage images which are encrypted with AES (ie if
              IMG_FLAG_ENC RYPTED_V1 flag is set).
              From a security standpoint, the IV does _not_ have to be
              secret in any way, but it _should_ be unique for every
              image which is encrypted with a given AES key.
    */
    _iv: [u8; 16],                      // space reserved for random data or timestamp to ensure IV is unique for every image which is signed
}
impl AImageHeader {
    //pub fn release_id_str(&self) -> String {
    //    let release_id_major = ((self.release_id) >> 21) & 0x3FF;
    //    let release_id_minor = ((self.release_id) >> 15) & 0x3F;
    //    let release_id_build = ((self.release_id) >> 1) & 0x3FFF;
    //    return format!("{}.{}-{}", release_id_major, release_id_minor, release_id_build)
    //}

    pub fn image_type_str(&self) -> &str {
        match self.image_type {
            0x00 => "invalid",          
            0x01 => "debug_message",
            0x02 => "bloader",
            0x03 => "slaveloader",      // [O]
            0x04 => "env",
            0x05 => "rbf",
            0x06 => "bootdata",         // [O] ROKUBOOT_TYPE_PKG
            0x07 => "cexapp",
            0x08 => "slaveapp",
            0x09 => "zimage",
            0x0A => "initfs_cramfs",    // [O] cramfs image
            0x0B => "initfs_zext2",
            0x0C => "appfs_ext2",
            0x0D => "appfs_cramfs",     // [O] custom_pkg image
            0x0E => "firmware_blob",    // [O] ROKUBOOT_TYPE_UBOOT   //main u-boot
            0x0F => "bootcount",
            0x10 => "bootselection",
            0x11 => "gnfs_ext2",        
            0x12 => "eth0mac",          
            0x13 => "bloader_testmode", 
            0x14 => "bloader_dfu",      
            0x15 => "splashscreen",    
            0x16 => "custom_pkg_token", // [O]
            0x17 => "initrd",
            0x18 => "uimage",           // [O] ROKUBOOT_TYPE_KERNEL // linux
            0x19 => "uboot_mipsel",
            0x1A => "uboot_mipseb",
            0x1B => "initfs_squashfs",
            0x101 => "cramfs_auth",     // [O] merkle tree for cramfs
            _ => "UNKNOWN",
        }
    }

    pub fn encmode_str(&self) -> &str {
        let encmode_flags = self.flags & (7 << 6);
        if (encmode_flags & (1 << 6)) != 0 {    // image data is encrypted before signing: CBC mode, entire image in one pass
            return "cbc_onepass"
        } else if (encmode_flags & (2 << 6)) != 0 {    // image data is encrypted before signing: CBC mode, 4k byte blocks, block group iv = (iv + (first block's block offset))
            return "cbc_4kblocks"
        } else if (encmode_flags & (3 << 6)) != 0 {    // image data is encrypted before signing: CTR mode, block iv = (iv + (block offset))
            return "ctr"
        } else {
            return "none/unknown"
        }
    }
}