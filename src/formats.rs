use std::any::Any;
use crate::AppContext;

pub struct Format {
    pub name: &'static str,
    pub detector_func: fn(&AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>>,
    pub extractor_func: fn(&AppContext, Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>>,
}

pub mod mstar;
pub mod samsung_old;
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
pub mod funai_upg_phl;
pub mod funai_bdp;
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

//define all formats here
pub fn get_registry() -> Vec<Format> {
    return vec![
        Format {
            name: "mstar",
            detector_func: crate::formats::mstar::is_mstar_file,
            extractor_func: crate::formats::mstar::extract_mstar,
        },
        Format {
            name: "samsung_old",
            detector_func: crate::formats::samsung_old::is_samsung_old_dir,
            extractor_func: crate::formats::samsung_old::extract_samsung_old,
        },
        Format {
            name: "nvt_timg",
            detector_func: crate::formats::nvt_timg::is_nvt_timg_file,
            extractor_func: crate::formats::nvt_timg::extract_nvt_timg,
        },
        Format {
            name: "pfl_upg",
            detector_func: crate::formats::pfl_upg::is_pfl_upg_file,
            extractor_func: crate::formats::pfl_upg::extract_pfl_upg,
        },
        Format {
            name: "sddl_sec",
            detector_func: crate::formats::sddl_sec::is_sddl_sec_file,
            extractor_func: crate::formats::sddl_sec::extract_sddl_sec,
        },
        Format {
            name: "novatek",
            detector_func: crate::formats::novatek::is_novatek_file,
            extractor_func: crate::formats::novatek::extract_novatek,
        },
        Format {
            name: "ruf",
            detector_func: crate::formats::ruf::is_ruf_file,
            extractor_func: crate::formats::ruf::extract_ruf,
        },
        Format {
            name: "invincible_image",
            detector_func: crate::formats::invincible_image::is_invincible_image_file,
            extractor_func: crate::formats::invincible_image::extract_invincible_image,
        },
        Format {
            name: "slp",
            detector_func: crate::formats::slp::is_slp_file,
            extractor_func: crate::formats::slp::extract_slp,
        },
        Format {
            name: "roku",
            detector_func: crate::formats::roku::is_roku_file,
            extractor_func: crate::formats::roku::extract_roku,
        },
        Format {
            name: "sony_bdp",
            detector_func: crate::formats::sony_bdp::is_sony_bdp_file,
            extractor_func: crate::formats::sony_bdp::extract_sony_bdp,
        },
        Format {
            name: "rvp",
            detector_func: crate::formats::rvp::is_rvp_file,
            extractor_func: crate::formats::rvp::extract_rvp,
        },
        Format {
            name: "funai_upg",
            detector_func: crate::formats::funai_upg::is_funai_upg_file,
            extractor_func: crate::formats::funai_upg::extract_funai_upg,
        },
        Format {
            name: "funai_upg_phl",
            detector_func: crate::formats::funai_upg_phl::is_funai_upg_phl_file,
            extractor_func: crate::formats::funai_upg_phl::extract_funai_upg_phl,
        },
        Format {
            name: "funai_bdp",
            detector_func: crate::formats::funai_bdp::is_funai_bdp_file,
            extractor_func: crate::formats::funai_bdp::extract_funai_bdp,
        },
        Format {
            name: "pana_dvd",
            detector_func: crate::formats::pana_dvd::is_pana_dvd_file,
            extractor_func: crate::formats::pana_dvd::extract_pana_dvd,
        },
        Format {
            name: "android_ota_payload",
            detector_func: crate::formats::android_ota_payload::is_android_ota_payload_file,
            extractor_func: crate::formats::android_ota_payload::extract_android_ota_payload,
        },
        Format {
            name: "bdl",
            detector_func: crate::formats::bdl::is_bdl_file,
            extractor_func: crate::formats::bdl::extract_bdl,
        },
        Format {
            name: "amlogic",
            detector_func: crate::formats::amlogic::is_amlogic_file,
            extractor_func: crate::formats::amlogic::extract_amlogic,
        },
        Format {
            name: "pup",
            detector_func: crate::formats::pup::is_pup_file,
            extractor_func: crate::formats::pup::extract_pup,
        },
        Format {
            name: "msd10",
            detector_func: crate::formats::msd10::is_msd10_file,
            extractor_func: crate::formats::msd10::extract_msd10,
        },
        Format {
            name: "msd11",
            detector_func: crate::formats::msd11::is_msd11_file,
            extractor_func: crate::formats::msd11::extract_msd11,
        },
        Format {
            name: "epk",
            detector_func: crate::formats::epk::is_epk_file,
            extractor_func: crate::formats::epk::extract_epk,
        },
        Format {
            name: "epk1",
            detector_func: crate::formats::epk1::is_epk1_file,
            extractor_func: crate::formats::epk1::extract_epk1,
        },
        Format {
            name: "epk2",
            detector_func: crate::formats::epk2::is_epk2_file,
            extractor_func: crate::formats::epk2::extract_epk2,
        },
        Format {
            name: "epk2b",
            detector_func: crate::formats::epk2b::is_epk2b_file,
            extractor_func: crate::formats::epk2b::extract_epk2b,
        },
        Format {
            name: "epk3",
            detector_func: crate::formats::epk3::is_epk3_file,
            extractor_func: crate::formats::epk3::extract_epk3,
        },
        Format {
            name: "mtk_pkg",
            detector_func: crate::formats::mtk_pkg::is_mtk_pkg_file,
            extractor_func: crate::formats::mtk_pkg::extract_mtk_pkg,
        },
        Format {
            name: "mtk_pkg_old",
            detector_func: crate::formats::mtk_pkg_old::is_mtk_pkg_old_file,
            extractor_func: crate::formats::mtk_pkg_old::extract_mtk_pkg_old,
        },
        Format {
            name: "mtk_pkg_new",
            detector_func: crate::formats::mtk_pkg_new::is_mtk_pkg_new_file,
            extractor_func: crate::formats::mtk_pkg_new::extract_mtk_pkg_new,
        },
        Format {
            name: "mtk_bdp",
            detector_func: crate::formats::mtk_bdp::is_mtk_bdp_file,
            extractor_func: crate::formats::mtk_bdp::extract_mtk_bdp,
        },

    ]
}