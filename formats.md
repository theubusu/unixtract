| Format name					| Used by																			| Notes																					| Thanks to																						|
| ----------------------------- | --------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Android OTA payload.bin		| Some Android MediaTek TVs															| Some compression methods are not supported											| https://android.googlesource.com/platform/system/update_engine/+/HEAD/update_metadata.proto	|
| EPK v1						| LG TVs before ~2010																| All files should be supported.														| https://github.com/openlgtv/epk2extract             											|
| EPK v2						| LG TVs since ~2010																| **Depends on keys** - see keys.rs														| https://github.com/openlgtv/epk2extract             											|
| EPK v3						| LG webOS TVs																		| **Depends on keys** - see keys.rs														| https://github.com/openlgtv/epk2extract             											|
| Funai UPG						| Some Funai TVs																	| Only supports unencrypted/unobfuscated files											| -                                                   											|
| INVINCIBLE_IMAGE				| LG Broadcom-based Blu-Ray players													| Only version 3 is supported (2011+)													| -                                                   											|
| MSD v1.0						| Samsung TVs 2013-2015																| **Depends on keys** - see keys.rs														| https://github.com/bugficks/msddecrypt              											|
| MSD v1.1						| Samsung TVs 2016+																	| **Depends on keys** - see keys.rs														| https://github.com/bugficks/msddecrypt              											|
| Mstar upgrade bin				| Many MStar-based TVs (Hisense, Toshiba..)											| Most files should be supported														| -                                                   											|
| Mediatek BDP					| Many Mediatek-based Blu-Ray players (LG, Samsung, Philips, Panasonic...)			| Some older files may not be supported													| -                                                   											|
| Mediatek PKG (Old)			| Older Mediatek-based TVs															| All files should be supported															| -                                                   											|
| Mediatek PKG					| Many Mediatek-based TVs (Hisense, Sony, Panasonic, Philips...)					| Newer files with larger header are not supported. **Depends on keys** - see keys.rs	| https://github.com/openlgtv/epk2extract             											|
| Novatek PKG (NFWB)			| Some Novatek-based TVs (Philips, LG..)											| All files should be supported															| https://github.com/openlgtv/epk2extract             											|
| Novatek TIMG					| Later Novatek Based TVs (Philips TitanOS/Hisense)									| All files should be supported															| -                                                   											|
| Panasonic Blu-Ray (PANA_DVD)	| Panasonic Blu-Ray Players/Recorders												| **Depends on keys** - see keys.rs														| -               																				|
| Philips UPG					| Philips pre-TPVision TVS 2008-2013												| **Depends on keys** - see keys.rs														| https://github.com/frederic/pflupg-tool             											|
| PUP							| Sony PlayStation 4/ PlayStation 5													| File has to be decrypted																| https://github.com/Zer0xFF/ps4-pup-unpacker         											|
| Roku							| Roku TVs/players																	| Most files should work, but encrypted images contained within will not be decrypted.	| -											          											|
| RUF							| Samsung Broadcom-based Blu-Ray players											| **Depends on keys** - see keys.rs														| -                                                   											|
| RVP/MVP						| Sharp Blu-Ray players/recorders													| Only supports older files (XOR encrypted)												| -                                                   											|
| Samsung						| Old Samsung TV firmwares pre 2013													| **Depends on keys** - see keys.rs														| https://github.com/george-hopkins/samygo-patcher    											|
| SDDL.SEC						| Panasonic TVs 2011+																| All files 2011+ are supported															| https://github.com/theubusu/sddl_dec                											|
| SLP							| Samsung Tizen-based NX series cameras												| All files should be supported															| -                                                   											|
| Sony BDP						| Sony Blu-Ray players																| Only platforms up to MSB18 are supported												| http://malcolmstagg.com/bdp/s390-firmware.html      											|