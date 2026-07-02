// UKF - custom key file format
// it is a simple custom data storing format that i made because nothing that exists fit my use case.
// you should be able to easily understand the structure by looking at the keys.ukf file
// the format does not define the structure or meaning of the contents. the caller needs to know the format they are stored in.

// there is two types of entries - key and collection
//entry starts with a keyword and the entry's name as a string (hex string cannot be used here) like - key "key_name": {...}

// key (Vec<Vec<u8>>) is a single key that can consist of one or many inner strings. a normal string - "hi"-  or hex string - x"6869" - can be used
// hex string is decoded automatically, there can be spaces and other whitespace in them.
// both normal string and string will be stored as Vec<u8>

// collection (Vec<(String, Vec<Vec<u8>>)>) is basically an array that contains many keys, used for iterating or indexing.\
// each key in the collection needs to be given a name before it like - "key1_name": {...} - but you can leave it empty. a comma may or may not follow the key entry, it doesnt matter

// line comments are supported with '#' character like in python

// i have also made UDL for notepad++ that makes it easier to edit and read the files. (only in dark mode version, and you scare me if you use light mode.)
// https://gist.github.com/theubusu/0e7a6d2d73375e9453c34e8972aaeb3e

use std::collections::HashMap;

// -- public definition --
#[derive(Debug)]
pub struct KeySystem {
    keys: HashMap<String, Vec<Vec<u8>>>,
    collections: HashMap<String, Vec<(String, Vec<Vec<u8>>)>>,
}
impl KeySystem {
    pub fn init(input: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut lexer = Lexer {input, pos: 0, line: 1};
        let tokens = lexer.tokenize()?;
        //println!("{:?}", tokens);
        let mut parser = Parser {tokens, pos: 0};
        parser.parse()
    }

    //gets a raw specified key
    pub fn get_key(&self, name: &str) -> Result<&Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        self.keys.get(name).ok_or_else(|| format!("key {name} not found").into())
    }

    //useful helper: gets a specified index in a key as an array
    pub fn get_key_as_arr<const N: usize>(&self, name: &str, idx: usize) -> Result<[u8; N], Box<dyn std::error::Error>> {
        Ok(self.get_key(name)?.get(idx).ok_or("key index out of range")?.as_slice().try_into()?)
    }

    //useful helper: gets a double key as tuple of arrays
    pub fn get_double_key_as_arr<const N1: usize, const N2: usize>(&self, name: &str) -> Result<([u8; N1], [u8; N2]), Box<dyn std::error::Error>> {
        let key = self.get_key(name)?;
        if key.len() != 2 {return Err(format!("key {} expected 2 parts, got {}", name, key.len()).into())};
        Ok((key[0].as_slice().try_into()?, key[1].as_slice().try_into()?))
    }

    //gets a raw specified collection
    pub fn get_collection(&self, name: &str) -> Result<&Vec<(String, Vec<Vec<u8>>)>, Box<dyn std::error::Error>> {
        self.collections.get(name).ok_or_else(|| format!("collection {name} not found").into())
    }
}

// tokens
#[derive(Debug,PartialEq, Clone)]
enum Token {
    Key,            // key entry marker
    Collection,     // collection entry marker
    HexStr(String), // x"" hexadecimal string
    Str(String),    // ""  quoted string
    Colon,          // :
    Comma,          // ,
    OpenBrace,      // {
    CloseBrace,     // }
}

// lexer
struct Lexer<'a> {
    input: &'a str,
    pos: usize,
    line: usize,
}
impl<'a> Lexer<'a> {
    //helper
    fn next(&self) -> Option<char> {
        self.input[self.pos..].chars().next()
    }
    fn advance(&mut self) -> Option<char> {
        let c = self.next()?;
        self.pos += c.len_utf8();
        if c == '\n' {self.line += 1; }  
        Some(c)
    }

    fn read_string(&mut self) -> Result<String, Box<dyn std::error::Error>> {
        let mut str = String::new();
        loop {
            match self.advance() {
                Some('"') => break,
                Some(c) => str.push(c),
                None => return Err(format!("line {} - string never closed", self.line).into())
            }
        }
        Ok(str)
    }

    fn tokenize(&mut self) -> Result<Vec<(Token, usize)>, Box<dyn std::error::Error>> {
        let mut tokens = Vec::new();
        loop {
            //skip whitespace and comments
            while let Some(c) = self.next() {
                if c == '#' {
                    while self.next().map(|ch| ch != '\n').unwrap_or(false) {self.advance();}
                } else if c.is_whitespace() {
                    self.advance();
                } else {
                    break;
                }
            }

            match self.next() {
                None => break,
                Some(':') => { self.advance(); tokens.push((Token::Colon, self.line)); }
                Some(',') => { self.advance(); tokens.push((Token::Comma, self.line)); }
                Some('{') => { self.advance(); tokens.push((Token::OpenBrace, self.line)); }
                Some('}') => { self.advance(); tokens.push((Token::CloseBrace, self.line)); }
                Some('x') => {  //hex string start
                    self.advance(); //skip x
                    if self.next() != Some('"') {
                        return Err(format!("line {} - unexpected character after hex string start", self.line).into());
                    }
                    self.advance(); //skip opening quotation mark
                    let string = self.read_string()?;
                    tokens.push((Token::HexStr(string), self.line));
                }
                Some('"') => {  //string start
                    self.advance(); //skip opening quotation mark
                    let string = self.read_string()?;
                    tokens.push((Token::Str(string), self.line));
                }
                Some(c) if c.is_alphabetic() || c == '_' => {   //entry marker
                    let mut entry = String::new();
                    while let Some(c) = self.next() {
                        if c.is_alphanumeric() || c == '_' {
                            entry.push(c);
                            self.advance();
                        } else {
                            break;
                        }
                    }
                    let entry_token = match entry.as_str() {
                        "key"        => Token::Key,
                        "collection" => Token::Collection,
                        unk => return Err(format!("line {} - unknown entry type {}", self.line, unk).into())
                    };
                    tokens.push((entry_token, self.line));
                }
                Some(c) => return Err(format!("line {} - unexpected character {}", self.line, c).into())
            }
        }
        Ok(tokens)
    }
}

//PARSER
struct Parser {
    tokens: Vec<(Token, usize)>,
    pos: usize,
}
impl Parser {
    //helper
    fn next(&self) -> Option<&(Token, usize)> {
        self.tokens.get(self.pos)
    }
    fn advance(&mut self) -> Option<&(Token, usize)> {
        let t = self.tokens.get(self.pos);
        self.pos += 1;
        t
    }

    //expect next token, with error log
    fn expect_next(&mut self, expected: &Token, ctx: &str) -> Result<(), Box<dyn std::error::Error>> {
        match self.advance() {
            Some((got, _)) if got == expected => Ok(()),
            Some((got, line)) => Err(format!("line {} - expected {:?} {}, got {:?}", line, expected, ctx, got).into()),
            None => Err(format!("unexpected end of file, expected {:?} {}", expected, ctx).into()),
        }
    }
    fn expect_next_str_get(&mut self, ctx: &str) -> Result<String, Box<dyn std::error::Error>> {
        match self.advance() {
            Some((Token::Str(s), _)) => Ok(s.clone()),
            Some((got, line)) => Err(format!("line {} - expected {} string, got {:?}", line, ctx, got).into()),
            None => Err(format!("unexpected end of file, expected {} string", ctx).into()),
        }
    }
    fn expect_next_hex_str_get(&mut self, ctx: &str) -> Result<(String, usize), Box<dyn std::error::Error>> {
        match self.advance() {
            Some((Token::HexStr(s), line)) => Ok((s.clone(), *line)),
            Some((got, line)) => Err(format!("line {} - expected {} hex string, got {:?}", line, ctx, got).into()),
            None => Err(format!("unexpected end of file, expected {} hex string", ctx).into()),
        }
    }

    //parse key block (like{"ABCD","0123",..})
    fn parse_key_block(&mut self) -> Result<Vec<Vec<u8>>, Box<dyn std::error::Error>> {
        self.expect_next(&Token::OpenBrace, "opening key block")?;
        let mut keys = Vec::new();
        loop {
            match self.next() {
                Some((Token::CloseBrace, _)) => { self.advance(); break; }  //end
                Some((Token::Str(_), _)) => {  
                    //normal string turns into Vec<u8>
                    let s= self.expect_next_str_get("value")?;
                    keys.push(s.as_bytes().to_vec());

                    //optional comma at end
                    if matches!(self.next(), Some((Token::Comma, _))) {
                        self.advance();
                    }
                }
                Some((Token::HexStr(_), _)) => {
                    //decode hex string to Vec<u8>
                    let (string, line) = self.expect_next_hex_str_get("value")?;
                    //remove whitespace
                    let clean: String = string.chars().filter(|c| !c.is_whitespace()).collect();

                    match hex::decode(&clean) {
                        Ok(bytes) => keys.push(bytes),
                        Err(e) => {return Err(format!("line {} - hex string decode error: {}", line, e).into())}
                    }

                    //optional comma at end
                    if matches!(self.next(), Some((Token::Comma, _))) {
                        self.advance();
                    }
                }
                Some((unk, line)) => {
                    return Err(format!("line {} - expected string or closing brace in key block, got {:?}", line, unk).into());
                }
                None => return Err("unexpected end of file in key block".into()),
            }
        }
        Ok(keys)
    }

    fn parse(&mut self) -> Result<KeySystem, Box<dyn std::error::Error>> {
        let mut system = KeySystem {
            keys: HashMap::new(),
            collections: HashMap::new(),
        };
        while let Some((token, line)) = self.next().cloned() {
            match token {
                Token::Key => {
                    //parse key entry
                    self.advance();
                    let name = self.expect_next_str_get("key name")?;
                    self.expect_next(&Token::Colon, "after key name")?;

                    let keys = self.parse_key_block()?;
                    if system.keys.insert(name.clone(), keys).is_some() {
                        return Err(format!("line {} - duplicate key {}", line, name).into());
                    }
                }
                Token::Collection => {
                    //parse collection entry
                    self.advance();
                    let name = self.expect_next_str_get("collection name")?;
                    self.expect_next(&Token::Colon, "after collection name")?;
                    self.expect_next(&Token::OpenBrace, "opening collection")?;

                    let mut entries = Vec::new();
                    loop {
                        match self.next() {
                            Some((Token::CloseBrace, _)) => {self.advance(); break; }
                            Some((Token::Str(_), _)) => {
                                let sub_name = self.expect_next_str_get("collection entry name")?;
                                self.expect_next(&Token::Colon, "after collection entry name")?;
                                //parse entry key block
                                let keys = self.parse_key_block()?;
                                entries.push((sub_name, keys));
                                //optional comma at end
                                if matches!(self.next(), Some((Token::Comma, _))) {
                                    self.advance();
                                }
                            }
                            Some((unk, line)) => {
                                return Err(format!("line {} - expected entry name or closing brace in collection,got {:?}", line, unk).into());
                            }
                            None => return Err("unexpected end of file in collection".into()),
                        }
                    }
                    if system.collections.insert(name.clone(), entries).is_some() {
                        return Err(format!("line {} - duplicate collection {}", line, name).into());
                    }
                }
                _ => return Err(format!("line {} - expected entry type marker, got {:?}", line, token).into()),
            }
        }
        Ok(system)
    }
}
