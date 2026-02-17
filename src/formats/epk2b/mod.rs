mod include;
use std::any::Any;
use crate::AppContext;

use std::path::{Path};
use std::fs::{self, OpenOptions};
use std::io::{Write, Seek, SeekFrom};
use binrw::BinReaderExt;

use crate::utils::common;
use include::*;

pub fn is_epk2b_file(app_ctx: &AppContext) -> Result<Option<Box<dyn Any>>, Box<dyn std::error::Error>> {
    let file = match app_ctx.file() {Some(f) => f, None => return Ok(None)};

    let epk2_magic = common::read_file(&file, 12, 4)?;
    let epak_magic = common::read_file(&file, 0, 4)?;
    if epak_magic == b"epak" && epk2_magic == b"EPK2" {
        Ok(Some(Box::new(())))
    } else {
        Ok(None)
    }
}

pub fn extract_epk2b(app_ctx: &AppContext, _ctx: Box<dyn Any>) -> Result<(), Box<dyn std::error::Error>> {
    let mut file = app_ctx.file().ok_or("Extractor expected file")?;

    let header: EpkHeader = file.read_le()?;
    println!("EPK info -\nData size: {}\nPak count: {}\nOTA ID: {}\nVersion: {:02x?}.{:02x?}.{:02x?}", 
            header.file_size, header.pak_count, header.ota_id(), header.version[2], header.version[1], header.version[0]);

    let mut paks: Vec<Pak> = Vec::new();

    for _i in 0..10 { //header can fit max 10 pak entries
        let pak: Pak = file.read_le()?;
        if pak.offset == 0 && pak.size == 0 {
            continue;
        }
        paks.push(Pak { offset: pak.offset, size: pak.size });
    }

    assert!(header.pak_count as usize == paks.len(), "Paks count in header does not match the amount of non empty pak entries!");

    for (i, pak) in paks.iter().enumerate() {
        file.seek(SeekFrom::Start(pak.offset as u64))?;
        let mut pak_header: PakHeader = file.read_le()?;

        let mut all_segment_size = 0;

        println!("\n({}/{}) - {}, Size: {}, Segment count: {}, Platform: {}", 
                i + 1, paks.len(), pak_header.pak_name(), pak_header.image_size, pak_header.segment_count, pak_header.platform_id());

        for i in 0..pak_header.segment_count {
            // for first segment we already read the header so skip doing that for it
            if i > 0 {
                pak_header = file.read_le()?;
            }

            assert!(i == pak_header.segment_index, "Unexpected segment index in pak header!, expected: {}, got: {}", i , pak_header.segment_index);

            println!("- Segment {}/{} - Size: {}", i + 1, pak_header.segment_count, pak_header.segment_size);
            let out_data = common::read_exact(&mut file, pak_header.segment_size as usize)?;
            all_segment_size += pak_header.segment_size;

            //for the last segment, the extra data should be calculated and stripped.
            let segment_limit = if i == pak_header.segment_count - 1 {
                let diff = all_segment_size - pak_header.image_size;
                pak_header.segment_size - diff
            } else {
                pak_header.segment_size
            };

            let output_path = Path::new(&app_ctx.output_dir).join(format!("{}.bin", pak_header.pak_name()));
            fs::create_dir_all(&app_ctx.output_dir)?;
            let mut out_file = OpenOptions::new().append(true).create(true).open(output_path)?;
            out_file.write_all(&out_data[..segment_limit as usize])?;

            println!("-- Saved to file!");
        }
    }

    println!("\nExtraction finished!");

    Ok(())
}