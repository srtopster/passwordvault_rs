use std::collections::BTreeMap;
use std::io::{Write,Read,BufReader,BufWriter,stdin,stdout};
use std::path::Path;
use std::fs::File;
use std::process;
use magic_crypt::{new_magic_crypt,MagicCryptTrait};
use serde_json;
use colored::*;
use rpassword;
use passwords::PasswordGenerator;
use clipboard::{ClipboardContext,ClipboardProvider};
mod windows_color;
use crossterm::{terminal::SetTitle,ExecutableCommand};

const DB_NAME: &str = "crypt.db";

fn read_input() -> String {
    let mut buffer = String::new();
    stdout().flush().unwrap();
    stdin().read_line(&mut buffer).unwrap();
    buffer.trim().to_owned()
}

fn wrong_pass(){
    println!("{}","Senha errada.".bright_red());
    println!("{}","=".repeat(50));
    println!("Aperte enter para sair.");
    stdout().flush().unwrap();
    stdin().read(&mut [0u8]).unwrap();
    process::exit(1);
}

fn show_on_terminal(mc: &magic_crypt::MagicCrypt256) {
    let json = match decript_file_to_json(mc,&Path::new(DB_NAME)) {
        Ok(json) => Some(json),
        Err(_) => None
    };
    if json == None {
        wrong_pass();
    }
    for (num,k_v) in json.unwrap().iter().enumerate() {
        println!("[{}] {}\n[>] {}",num,k_v.0.bright_green().underline(),k_v.1.bright_red())
    }
}

fn save_password(mc: &magic_crypt::MagicCrypt256,title: String,pass: String) {
    println!("{}","Decriptando...".bright_cyan());
    let json = match decript_file_to_json(&mc,&Path::new(DB_NAME)) {
        Ok(json) => Some(json),
        Err(_) => {
            if File::open(Path::new(DB_NAME)).unwrap().metadata().unwrap().len() == 0 {
                let new: BTreeMap<String, String> = BTreeMap::new();
                Some(new)
            }else {
                None
            }
        }
    };
    if json == None {
        wrong_pass();
    }

    println!("{}","Salvando senha...".bright_cyan());
    let mut json = json.unwrap();
    json.insert(title, pass);
    println!("{}","Encriptando...".bright_cyan());
    encript_json_to_file(&mc,&Path::new(DB_NAME),json);
    println!("{}","=".repeat(50));
    println!("{}","Senha salva com sucesso".bright_green());
    println!("{}","=".repeat(50));
}

fn extract_to_txt(mc: &magic_crypt::MagicCrypt256) {
    let json = match decript_file_to_json(mc,&Path::new(DB_NAME)) {
        Ok(json) => Some(json),
        Err(_) => None
    };
    if json == None {
        wrong_pass();
    }
    let f = File::create(format!("{}.txt",DB_NAME)).expect("Erro ao criar arquivo .txt");
    let mut buff = BufWriter::new(f);
    for (key,value) in json.unwrap() {
        buff.write(format!("{:20} : {}\n",key,value).as_bytes()).unwrap();
    }
    buff.write_all(format!(
    "\n==================================================\n\
    Este arquivo não é seguro/Delete-o quando terminar\n\
    ==================================================").as_bytes()).unwrap();
    println!("{}","Salvo no arquivo: database.txt".bright_green())
}

fn random_password(size: usize) -> String {
    let pg = PasswordGenerator {
        length: size,
        numbers: true,
        lowercase_letters: true,
        uppercase_letters: true,
        symbols: true,
        spaces: false,
        exclude_similar_characters: false,
        strict: true,
    };
    pg.generate(1).unwrap()[0].to_owned()
}

fn decript_file_to_json(mc: &magic_crypt::MagicCrypt256,path: &Path) -> Result<BTreeMap<String,String>, magic_crypt::MagicCryptError>{
    let in_file = File::open(path).unwrap();
    match mc.decrypt_reader_to_bytes(&mut BufReader::new(in_file)) {
        Ok(bytes) => {
            let json: BTreeMap<String,String> = serde_json::from_slice(&bytes).unwrap();
            return Ok(json)
        },
        Err(error) => {
           return Err(error)
        }
    }
}

fn encript_json_to_file(mc: &magic_crypt::MagicCrypt256,path: &Path,json: BTreeMap<String,String>){
    let out_file = File::create(path).expect("Não foi possivel criar o arquivo.");
    let buffer = serde_json::to_vec_pretty(&json).unwrap();
    let enc_bytes = mc.encrypt_bytes_to_bytes(&buffer);
    BufWriter::new(out_file).write_all(&enc_bytes).expect("Não foi possivel escrever no arquivo.");
}

fn main() {
    stdout().execute(SetTitle("Password Vault")).unwrap();
    windows_color::enable_ansi_support().expect("Falha ao setar cores para windows.");
    if !Path::new(DB_NAME).exists() {
        File::create(DB_NAME).unwrap();
        println!("{}","Arquivo crypt.db criado.".bright_green())
    }
    if File::open(Path::new(DB_NAME)).unwrap().metadata().unwrap().len() == 0 {
        println!("{}","================================= ATENÇÃO =================================".bright_red());
        println!("{}",format!("O arquivo {} está vazio.",DB_NAME).bright_red());
        println!("{}","Você deve salvar alguma senha antes de tentar acessar o banco de dados.".bright_red());
        println!("{}","A senha usada para acessar o banco de dados será a senha sua futura senha.".bright_red());
        println!("{}","===========================================================================".bright_red());
    }
    println!("{}","=".repeat(50));
    println!("{}","Bem Vindo ao Password Vault".bright_cyan());
    println!("{}","=".repeat(50));
    println!("1 - Acessar o banco de dados");
    println!("2 - Adicionar uma senha customizada");
    println!("3 - Gerar uma senha");
    print!("> ");
    let ch1 = read_input();
    println!("{}","=".repeat(50));
    if ch1 == "1" {
        println!("{}","Deseja".bright_cyan());
        println!("{}","=".repeat(50));
        println!("1 - Mostrar no programa (Seguro)");
        println!("2 - Extrair para um .txt (Não seguro)");
        print!("> ");
        let ch2 = read_input();
        if ch2 != "1" && ch2 != "2" {println!("Insira uma opção valida.");process::exit(1)}
        println!("{}","=".repeat(50));
        println!("Digite a senha para o banco de dados:");
        stdout().flush().unwrap();
        let pw = rpassword::prompt_password("> ").unwrap();
        println!("{}","=".repeat(50));
        let mc = new_magic_crypt!(pw,256);
        println!("{}","Decriptando...".bright_cyan());
        println!("{}","=".repeat(50));
        if ch2 == "1" {
            show_on_terminal(&mc);
        }else if ch2 == "2" {
            extract_to_txt(&mc)
        }
        println!("{}","=".repeat(50));
        println!("{}","Decriptado com sucesso.".bright_green());
        println!("{}","=".repeat(50));
    }else if ch1 == "2" {
        println!("Digite um nome/user para essa senha:");
        print!("> ");
        let title = read_input();
        stdout().flush().unwrap();
        let upw1 = rpassword::prompt_password("Digite a senha: ").unwrap();
        stdout().flush().unwrap();
        let upw2 = rpassword::prompt_password("Repita a senha: ").unwrap();
        if upw1 != upw2 {println!("As senhas não combimam.");process::exit(1)}
        println!("{}","=".repeat(50));
        println!("Digite a senha para o banco de dados: ");
        stdout().flush().unwrap();
        let pw = rpassword::prompt_password("> ").unwrap();
        println!("{}","=".repeat(50));
        let mc = new_magic_crypt!(pw,256);
        save_password(&mc, title, upw1)
    }else if ch1 == "3" {
        println!("Digite o tamanho da senha: ");
        print!("> ");
        let pass_length = read_input();
        if !pass_length.parse::<usize>().is_ok() {
            println!("Digite um número válido.")
        }
        let rngpass = random_password(pass_length.parse::<usize>().unwrap());
        let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
        ctx.set_contents(rngpass.to_owned()).unwrap();
        println!("{}","=".repeat(50));
        println!("Sua senha: {}",rngpass.bright_green());
        println!("Senha copiada para a área de transferência.");
        println!("{}","=".repeat(50));
    }else {
        println!("{}","Insira uma opção valida.".bright_red())
    }
    println!("Aperte enter para sair.");
    stdout().flush().unwrap();
    stdin().read(&mut [0u8]).unwrap();
}