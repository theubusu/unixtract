# unixtract
Extractor for various file formats.   
This is a tool that is able to extract the contents of various firmware package formats, mostly from TVs and AV devices.   
Built in Rust, and made to not depend on any external dependancies, only Rust crates. This way it can work on Windows, Linux and MacOS and even Android.   
Please note that this project is still under active development and errors may occur. Feel free to make an issue in that case, or if you have any feature request.   
   
**PLEASE NOTE** - this program is NOT, and will never be designed for re-packing the extracted files!

# Installation
You can download the latest auto build for Windows and Linux x86-64 from [here](https://nightly.link/theubusu/unixtract/workflows/rust/main).   
Or, build from source, by downloading the code or cloning the respository and running `cargo build --release`. The binary will be saved in `target/release`.  

# Usage
`unixtract [OPTIONS] <INPUT_TARGET> [OUTPUT_FOLDER]`  
Arguments:   
`<INPUT_TARGET>` - The target to analyze/extract.  
`[OUTPUT_FOLDER]` - Folder to save extracted files to. If not provided, extracted files will be saved in folder `_<INPUT_TARGET>`.   
Options:  
`-o, --options <OPTIONS>` - Format specific or global(for all formats that implement it) options, see the list below for format specific options. You can use this multiple times to activate multiple options.    
`-k, --key-file [KEY_FILE]` - Path to the ukf key file. If not provided, the built in file will be used.  
## Global options
`dump_dec_hdrs` - For formats with an encrypted header - dump the decrypted header(s).    

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

## BEM
**Used in:** Samsung Signage(LFD)/Hospitality displays  
**Common names:** `swuimage.bem`   
**Notes:** **Depends on keys** - see keys.ukf (uses MSD11 keys)  

## CD5  
**Used in:** Some Samsung TV tuners, and possibly other Irdeto(?)-based tuners  
**Common names:** `MainAppImage.cd5`   
**Notes:** Decryption is not supported.

## EPK v1  
**Used in:** LG TVs before ~2010  
**Notes:** None, all files should be supported  
**Thanks to:** https://github.com/openlgtv/epk2extract

## EPK v2  
**Used in:** LG TVs since ~2010  
**Notes:** **Depends on keys** - see keys.ukf (most common keys should be included)  
**Thanks to:** https://github.com/openlgtv/epk2extract   
**Options:**   
※ Support `dump_dec_hdrs` option

## EPK v3  
**Used in:** LG webOS-based TVs  
**Notes:** **Depends on keys** - see keys.ukf  
**Thanks to:** https://github.com/openlgtv/epk2extract   
**Options:**   
※ Support `dump_dec_hdrs` option

## FDAT  
**Used in:** Sony Digital cameras and camcorders  
**Notes:** Supports: CXD4105/MB8AC102, CXD4115, CXD4120, CXD4132, CXD90014, CXD90045  
**Thanks to:** https://github.com/ma1co/fwtool.py   
**Options:**   
※ Support `dump_dec_hdrs` option

## Funai BDP   
**Used in:** Funai & Funai-made Philips Blu-Ray player/HTS (USA market)  
**Notes:** N/A   

## Funai MStar   
**Used in:** MStar-based Funai & Funai-made Philips TVs (USA market)  
**Notes:** Inner SoC part is extracted with mstar_secure_old    

## Funai UPG   
**Used in:** Some Funai TVs  
**Notes:** **Depends on keys** - see keys.ukf.    

## Funai UPG PHL   
**Used in:** Funai & Funai-made Philips TVs (USA market)  
**Notes:** **Depends on keys** - see keys.ukf (most common keys should be included).    

## GX DVB
**Used in:** Cheap NationalChip GX-based DVB tuners    
**Notes:** None, all files should be supported

## INVINCIBLE_IMAGE   
**Used in:** LG Broadcom-based Blu-Ray players  
**Notes:** Key ID 1 (<2010) is not supported.   
Tip: if you have split ROM (.ROM-00 and .ROM-01), extract both into the same folder so they get combined.       

## MSD 1.0
**Used in:** Samsung TVs 2013-2015  
**Common names:** `upgrade.msd`   
**Notes:** **Depends on keys** - see keys.ukf  
**Thanks to:** https://github.com/bugficks/msddecrypt  
**Options:**   
`msd10:save_cmac` - Save CMAC data for files that is skipped by default.   
`msd:print_ouith` - Prints the entire parsed OUITH header.  
※ Support `dump_dec_hdrs` option

## MSD 1.1
**Used in:** Samsung TVs 2016+  
**Common names:** `upgrade.msd`   
**Notes:** **Depends on keys** - see keys.ukf  
**Thanks to:** https://github.com/bugficks/msddecrypt  
**Options:**   
`msd:print_ouith` - Prints the entire parsed OUITH header.  
※ Support `dump_dec_hdrs` option

## MSFirm  
**Used in:** Sony Digital cameras  
**Notes:** Supports: CXD4105, CXD4108     
**Thanks to:** https://github.com/ma1co/fwtool.py   
**Options:**   
※ Support `dump_dec_hdrs` option

## MStar upgrade bin
**Used in:** Many MStar-based TVs (Hisense, Toshiba...)  
**Common names:** `MStarUpgrade.bin`   
**Notes:** All files should be supported, includes lzop, lz4, lzma, sparse_write support  
**Options:**  
`mstar:keep_unknown` - Save data with unknown destination.  
※ Support `dump_dec_hdrs` option (will save the script)   

## MStar upgrade bin (Secure, old)
**Used in:** Older MStar-based TVs with Secure upgrade mode (encrypted+signed)  
**Notes:** Only default upgrade key is supported. This use the extractor above after decrypting.  
**Options:**  
`mstar_secure_old:keep_decrypted` - Keep decrypted file (it will be deleted by default).  

## MediaTek BDP
**Used in:** Many MediaTek-based Blu-Ray players (LG, Samsung, Philips, Panasonic...)  
**Notes:** Some older files may fail to extract  

## MediaTek PKG (New)
**Used in:** Newer MediaTek-based TVs (TCL, Hisense, Sony, Philips, CVT...)  
**Notes:** **Depends on keys** - see keys.ukf (Keys for Philips and Sony included)  
**Options:**        
※ Support `dump_dec_hdrs` option

## MediaTek PKG (Old)
**Used in:** Older MediaTek-based TVs (Philips, Sony, Hisense...)  
**Common names:** `upgrade_loader.pkg`   
**Notes:** All files should be supported, decryption + decompression   
**Options:**       
※ Support `dump_dec_hdrs` option

## MediaTek PKG
**Used in:** MediaTek-based TVs (Sony, Philips, Panasonic, Sharp...)  
**Notes:** All files should be supported, decryption + decompression, however some Philips files use custom keys - most are included some could be missing  
**Thanks to:** https://github.com/openlgtv/epk2extract   
**Options:**     
※ Support `dump_dec_hdrs` option

## Novatek PKG (NFWB)
**Used in:** Some older Novatek-based TVs (LG, Philips)  
**Notes:** None, all files should be supported.

## Novatek BIN
**Used in:** Some Vestel(?) Novatek-based TVs. Usually accompanied by a .scr file, but it is not needed for extraction.  
**Common names:** `kylo_usb_update.bin`   
**Notes:** None, all files should be supported.

## Novatek TIMG
**Used in:** Newer Novatek-based TVs (Philips(TPVision), Hisense, TCL...)  
**Notes:** None, all files should be supported.   

## Onkyo
**Used in:** Onkyo AVRs and other AV devices  
**Notes:** Newer files seem to use a different encryption and are not (yet) supported.   
**Thanks to:** http://divideoverflow.com/2014/04/decrypting-onkyo-firmware-files/   
**Options:**   
※ Support `dump_dec_hdrs` option

## Panasonic Blu-Ray
**Used in:** Panasonic Blu-Ray Players and Recorders  
**Common names:** `PANA_DVD.FRM`, `PANA_ESD.FRM`, `PANAEDVD.FRM`      
**Notes:** **Depends on keys** - see keys.ukf (Included keys should work for 99% of players released in and before 2014, and some released in 2018), Note that there is currently an issue with MAIN in some very ancient files not extracting correctly.   
**Options:**   
`pana_dvd:split_main` - Automatically split the MAIN module into seperate partitions.   
※ Support `dump_dec_hdrs` option

## Philips UPG (2SWU3TXV)
**Used in:** Philips pre-TPVision TVs 200?-2013 and some Sony TVs   
**Common names:** `autorun.upg`   
**Notes:** **Depends on keys** - see keys.ukf  
**Thanks to:** https://github.com/frederic/pflupg-tool   
**Options:**   
`pfl_upg:no_extract_inner_upg` - Do not automatically extract inner UPGs. (Warning: this can cause file collisions sometimes!)   

## Philips BDP   
**Used in:** Philips MediaTek-based Blu-ray players/Home theatre systems     
**Notes:** The main partition (ID 0) can be sometimes encrypted, and there is no good way to detect that. So if MTK BDP extraction fails, try running with `philips_bdp:decrypt` option.     
**Options:**   
`philips_bdp:decrypt` - Decrypt main partition   

## PUP
**Used in:** Sony PlayStation 4/5  
**Notes:** File has to be decrypted.  
**Thanks to:** https://github.com/Zer0xFF/ps4-pup-unpacker

## Roku
**Used in:** Roku TV's/players  
**Common names:** `update.roku`   
**Notes:** The contents of the update file can be extracted, but some firmware images contained inside are additionally encrypted, and they cannot be decrypted as of now. 

## RUF
**Used in:** Samsung Broadcom-based Blu-Ray players  
**Notes:** **Depends on keys** - see keys.ukf 

## RVP/MVP
**Used in:** Sharp Blu-Ray players/recorders  
**Notes:** Only the older types of files are supported (XOR-encrypted) 

## Samsung (Folder with ***.img.sec)
**Used in:** Samsung TVs pre 2013  
**Notes:** **Depends on keys** - see keys.ukf  
**Thanks to:** https://github.com/george-hopkins/samygo-patcher

## SDBoot
**Used in:** Panasonic TVs SD boot   
**Notes:** There is only one known sample, so support may vary.  
**Base:** https://github.com/theubusu/sddl_dec

## SDDL.SEC
**Used in:** Panasonic TVs   
**Common names:** `SDDL.SEC`   
**Notes:** None, all files should be supported.  
**Options:**   
`sddl_sec:save_extra` - Save SDIT.FDI and .TXT files that are not extracted by default.   
`sddl_sec:split_peaks` - Split PEAKS module into partitions (only on older files). This will also automatically decompress compressed partitions.   
`sddl_sec:no_decomp_peaks` - Do not automatically decompress partitions when splitting PEAKS with above option.  
**Base:** https://github.com/theubusu/sddl_dec

## SDImage
**Used in:** Some 2010 USA Panasonic TVs  
**Common names:** `SDImage.bin`     
**Notes:** Decryption is not yet supported.  

## SLP
**Used in:** Samsung Tizen-based NX series cameras  
**Notes:** None, all files should be supported. 

## Sony BDP
**Used in:** Sony MediaTek-based Blu-Ray players  
**Common names:** `MSBXX-FW.bin`, `MSBXX-FW_MB.bin`  
**Notes:** **Depends on keys** - see keys.ukf (Platforms up to MSB29 are supported)  
**Thanks to:** http://malcolmstagg.com/bdp/s390-firmware.html  

## TSB Bin
**Used in:** Older Toshiba TVs  
**Common names:** `bootimg.prg`, `eutvXXXX.prg`   
**Notes:** None, all files should be supported.   
**Options:**   
※ Support `dump_dec_hdrs` option

# License
Licensed under GNU GPL v3.  
