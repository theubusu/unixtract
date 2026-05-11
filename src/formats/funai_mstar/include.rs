use std::collections::HashMap;

#[derive(Debug)]
pub struct InfoStruct {
    pub file_code: String,
    pub brand_name: String,
    pub model_name: String,
    pub soc_version: String,
    pub frc_version: String,
    pub soc_size: usize,
    pub frc60_size: usize,
    pub frc120_size: usize,
}
impl InfoStruct {
    pub fn from_str(str: String) -> Option<Self> {
        let lines: Vec<&str> = str.lines().map(|l| l.trim()).collect();
        let mut map = HashMap::new();

        for line in lines {
            //skip markers
            if line == "#@INFO" || line == "#@END" {
                continue;
            }

            //split KEY=VALUE
            let (key, value) = line.split_once('=')?;
            map.insert(key, value);
        }

        Some(Self {
            file_code: map.get("FileCode")?.to_string(),
            brand_name: map.get("BrandName")?.to_string(),
            model_name: map.get("ModelName")?.to_string(),
            soc_version: map.get("SoC_Version")?.to_string(),
            frc_version: map.get("FRC_Version")?.to_string(),

            soc_size: map.get("SoC_Size")?.parse().ok()?,
            frc60_size: map.get("FRC60_Size")?.parse().ok()?,
            frc120_size: map.get("FRC120_Size")?.parse().ok()?,
        })
    }
}