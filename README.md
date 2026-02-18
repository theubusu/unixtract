# unixtract
Extractor for various file formats.   
This is a tool that is able to extract the contents of various firmware package formats, mostly from TVs and AV devices.   
Built in Rust, and made to not depend on any external dependancies, only Rust crates. This way it can work on Windows, Linux and MacOS and even Android without any issue.   
Please note that this project is still under active development and errors may occur. Feel free to make an issue in that case, or if you have any feature request.   

# Installation
Build from source, by downloading the code or cloning the respository and running `cargo build --release`. The binary will be saved in `target/release`.  

# Usage
`unixtract [OPTIONS] <INPUT_TARGET> [OUTPUT_FOLDER]`  
Arguments:   
`<INPUT_TARGET>` - The target to analyze/extract.  
`[OUTPUT_FOLDER]` - Folder to save extracted files to.  
If an output folder is not provided, extracted files will be saved in folder `_<INPUT_TARGET>`.   
Options:  
`-o, --options <OPTIONS>` - Format specific or global(for all formats that implement it) options, see the list below for format specific options. You can use this multiple times to activate multiple options.    

# Supported formats
## Amlogic burning image  
**Used in:** Android TVs and Boxes   
**Notes:** V1 format is not supported because of the lack of sample file.  
**Thanks to:** https://github.com/7Ji/ampack

## Android OTA payload.bin  
**Used in:** Android devices, smartphones, TVs   
**Notes:** Some compression methods may not be supported.  
**Thanks to:** https://android.googlesource.com/platform/system/update_engine/+/HEAD/update_metadata.proto

## BDL  
**Used in:** Enterprise HP Printers  
**Notes:** None, all files should be supported

## EPK v1  
**Used in:** LG TVs before ~2010  
**Notes:** None, all files should be supported  
**Thanks to:** https://github.com/openlgtv/epk2extract

## EPK v2  
**Used in:** LG TVs since ~2010  
**Notes:** **Depends on keys** - see keys.rs (most common keys should be included)  
**Thanks to:** https://github.com/openlgtv/epk2extract

## EPK v3  
**Used in:** LG webOS-based TVs  
**Notes:** **Depends on keys** - see keys.rs  
**Thanks to:** https://github.com/openlgtv/epk2extract

## Funai UPG   
**Used in:** Some Funai TVs  
**Notes:** Decryption is not yet supported.    

## INVINCIBLE_IMAGE   
**Used in:** LG Broadcom-based Blu-Ray players  
**Notes:** Only version 3 is supported (2011+)    

## MSD 1.0
**Used in:** Samsung TVs 2013-2015  
**Notes:** **Depends on keys** - see keys.rs  
**Thanks to:** https://github.com/bugficks/msddecrypt  
**Options:**   
`msd10:save_cmac` - Save CMAC data for files that is skipped by default.

## MSD 1.1
**Used in:** Samsung TVs 2016+  
**Notes:** **Depends on keys** - see keys.rs (keys 2015-2018, 2020 included)  
**Thanks to:** https://github.com/bugficks/msddecrypt  

## MStar upgrade bin
**Used in:** Many MStar-based TVs (Hisense, Toshiba...)  
**Notes:** All files should be supported, includes lzop, lz4, lzma, sparse_write support  

## MediaTek BDP
**Used in:** Many MediaTek-based Blu-Ray players (LG, Samsung, Philips, Panasonic...)  
**Notes:** Some older files may fail to extract  

## MediaTek PKG (New)
**Used in:** Newer MediaTek-based TVs (TCL, Hisense, Sony, Philips, CVT...)  
**Notes:** **Depends on keys** - see keys.rs (Keys for Philips and Sony included)  

## MediaTek PKG (Old)
**Used in:** Older MediaTek-based TVs (Philips, Sony, Hisense...)  
**Notes:** All files should be supported, decryption + decompression 

## MediaTek PKG
**Used in:** MediaTek-based TVs (Sony, Philips, Panasonic, Sharp...)  
**Notes:** All files should be supported, decryption + decompression, however some Philips files use custom keys - most are included some could be missing  
**Thanks to:** https://github.com/openlgtv/epk2extract

## Novatek PKG (NFWB)
**Used in:** Some older Novatek-based TVs (LG, Philips)  
**Notes:** None, all files should be supported.

## Novatek TIMG
**Used in:** Newer Novatek-based TVs (Philips TitanOS, Hisense)  
**Notes:** There is an older type of this format that is not yet supported, but for newer type all files should work. 

## Panasonic Blu-Ray (PANA_DVD.FRM, PANA_ESD.FRM, PANAEUSB.FRM)
**Used in:** Panasonic Blu-Ray Players and Recorders  
**Notes:** **Depends on keys** - see keys.rs (Included keys should work for 99% of players released in and before 2014, and some released in 2018), Note that there is currently an issue with MAIN in some very ancient files not extracting correctly. 
**Options:**   
`pana_dvd:split_main` - Automatically split the MAIN module into seperate partitions.

## Philips UPG (Autorun.upg, 2SWU3TXV)
**Used in:** Philips pre-TPVision TVs 200?-2013  
**Notes:** **Depends on keys** - see keys.rs  
**Thanks to:** https://github.com/frederic/pflupg-tool

## PUP
**Used in:** Sony PlayStation 4/5  
**Notes:** File has to be decrypted.  
**Thanks to:** https://github.com/Zer0xFF/ps4-pup-unpacker

## Roku
**Used in:** Roku TV's/players  
**Notes:** The contents of the update file can be extracted, but some firmware images contained inside are additionally encrypted, and they cannot be decrypted as of now. 

## RUF
**Used in:** Samsung Broadcom-based Blu-Ray players  
**Notes:** **Depends on keys** - see keys.rs 

## RVP/MVP
**Used in:** Sharp Blu-Ray players/recorders  
**Notes:** Only the older types of files are supported (XOR-encrypted) 

## Samsung (Folder with ***.img.sec)
**Used in:** Samsung TVs pre 2013  
**Notes:** **Depends on keys** - see keys.rs  
**Thanks to:** https://github.com/george-hopkins/samygo-patcher

## SDDL.SEC
**Used in:** Panasonic TVs  
**Notes:** Pre-2011 files are not supported.  
**Options:**   
`sddl_sec:save_extra` - Save SDIT.FDI and .TXT files that are not extracted by default.

## SLP
**Used in:** Samsung Tizen-based NX series cameras  
**Notes:** None, all files should be supported. 

## Sony BDP
**Used in:** Sony Blu-Ray players  
**Notes:** Only platforms up to MSB18 are supported.  
**Thanks to:** http://malcolmstagg.com/bdp/s390-firmware.html  

# License
Licensed under GNU GPL v3.  