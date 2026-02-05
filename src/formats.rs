use std::any::Any;
use crate::ProgramContext;

pub struct Format {
    pub name: &'static str,
    pub detect_func: fn(&ProgramContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>>,
    pub run_func: fn(&ProgramContext, Option<Box<dyn Any>>) -> Result<(), Box<dyn std::error::Error>>,
}

pub mod mstar;
//pub mod samsung_old; not sure what to do with this
pub mod nvt_timg;
pub mod pfl_upg;
pub mod sddl_sec;
pub mod novatek;
pub mod ruf;
pub mod invincible_image;
pub mod slp;
pub mod roku;
pub mod sony_bdp;
pub mod rvp;
pub mod funai_upg;
pub mod pana_dvd;
pub mod android_ota_payload;
pub mod bdl;
pub mod amlogic;

pub mod pup;

pub mod msd;
pub mod msd10;
pub mod msd11;

pub mod epk;
pub mod epk1;
pub mod epk2;
pub mod epk2b;
pub mod epk3;

pub mod mtk_pkg;
pub mod mtk_pkg_old;
pub mod mtk_pkg_new;
pub mod mtk_bdp;

pub fn get_registry() -> Vec<Format> {
    return vec![
        crate::formats::amlogic::format(),
        crate::formats::epk1::format(),
        crate::formats::android_ota_payload::format(),
        crate::formats::bdl::format(),
        crate::formats::epk2::format(),
        crate::formats::epk::format(),
        crate::formats::epk2b::format(),
        crate::formats::funai_upg::format(),
        crate::formats::invincible_image::format(),
        crate::formats::msd10::format(),
        crate::formats::msd11::format(),
        crate::formats::mstar::format(),
        crate::formats::novatek::format(),
        crate::formats::nvt_timg::format(),
        crate::formats::pfl_upg::format(),
        crate::formats::pup::format(),
        crate::formats::roku::format(),
        crate::formats::ruf::format(),
        crate::formats::rvp::format(),
        crate::formats::sddl_sec::format(),
        crate::formats::slp::format(),
        crate::formats::mtk_pkg_old::format(),
        crate::formats::mtk_pkg::format(),
        crate::formats::sony_bdp::format(),
        crate::formats::mtk_pkg_new::format(),
        crate::formats::pana_dvd::format(),
        crate::formats::mtk_bdp::format(),
    ]
}