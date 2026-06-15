# unixtract ng2

This branch is a concept of a new architecture rewrite for unixtract work-in-progress.  
It is inspired by 7-zip architecture (each format has an open and extract function, Open will return an instance of the format file, and then you can call extract on the individual items.)   
Not sure if this will ever become the main branch, this is just messing around seeing how the architecture can be improved.
Why ng2? Because there was already an ng, but i scrapped it.

Planned Features:  
- More modular, cleaner and unified architecture
- Can extract from memory source instead of a set File type
- Allows to extract and get generic info about singular items from inside the file
- Logging with verbose levels
- Improved key system (maybe load from json file, but also include in compiled binary), here i havent decided on the format yet, json annoys me because it doesnt have comments, i tried TOML and YAML but didnt make the decision yet. and apparentally yaml is bad

Issues that will be faced:  
- Nested formats ( no idea how to implement them for now)
- If filename can change in extract process (only one i can think of is sddl_sec inner file)
- Directory based formats (only samsung_old, it will be deprecated, it needed to go anyway farewell)
- in mtk_bdp ive noticed, there is multiple entries in the file with the same name but pointing at a different offest in the src. normally this is not an issue since they are all extracted into same file. and here they also are so is this really an issue? im not sure

Im thinking whether lzop and sparse should become their own formats. But all of the compressions arent formats, and LZOP and sparse are a type of compression so im not sure here. But i would like an option to decomp lzop since nothing on windows can do it seemingly

I know, this branch is a big mess right now with all of the unported files, (and everything else) but i have decided to keep it like that to not ruin the history with file deletion. and this is just TESTING!!! dead code is ALLOWED unlike main branch

## LIST: Currently ported formats (4/40):
- `invincible_image`
- `mtk_bdp`
- `novatek`
- `tsb_bin`
