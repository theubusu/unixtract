# unixtract
Extractor for various file formats.   
This is a tool that is able to extract the contents of various firmware package formats.   
Built in Rust, and made to not depend on any external dependancies, only Rust crates. This way it can work on Windows, Linux and MacOS without any issue.   
Please note that this project is still mostly under development and errors may occur. Feel free to make an issue in that case.   

# Usage
`unixtract <INPUT_TARGET> [OUTPUT_FOLDER]`   
`<INPUT_TARGET>` - The target to analyze/extract.  
`[OUTPUT_FOLDER]` - Folder to save extracted files to.  
If an output folder is not provided, extracted files will be saved in folder `_<INPUT_TARGET>`.   

# Supported formats