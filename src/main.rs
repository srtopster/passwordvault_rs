use std::collections::BTreeMap;
use std::io::{Write,Read,BufReader,BufWriter,stdin,stdout};
use std::path::Path;
use std::fs::File;
use std::{process,env};
use magic_crypt::{new_magic_crypt,MagicCryptTrait};
use serde_json;
use colored::*;
use inquire::{Select,Password,PasswordDisplayMode,validator::Validation};
use passwords::PasswordGenerator;
use clipboard::{ClipboardContext,ClipboardProvider};
mod windows_color;
use crossterm::{terminal::{SetTitle,Clear,ClearType},cursor::MoveTo,ExecutableCommand};

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

fn password_twice(text_promp: &str) -> String {
    let pw1 = Password::new(text_promp)
    .with_display_mode(PasswordDisplayMode::Masked)
    .prompt()
    .expect("Falha ao ler senha");

    let validator = move |input: &str| if input != pw1 {
        Ok(Validation::Invalid("As senhas devem combinar !".into()))
    } else {
        Ok(Validation::Valid)
    };

    let pw2 = Password::new("Repita a senha:")
    .with_display_mode(PasswordDisplayMode::Masked)
    .with_validator(validator)
    .prompt()
    .expect("Falha ao ler senha");
    
    pw2
}

fn edit_mode() {
    println!("{}","=".repeat(50));
    println!("{}","Bem vindo ao modo de edição".bright_cyan());
    println!("{}","=".repeat(50));
    let pw = Password::new("Digite a senha para o banco de dados:\n>").with_display_mode(PasswordDisplayMode::Masked).prompt().expect("Erro ao ler senha");
    let mc = new_magic_crypt!(pw,256);
    println!("{}","=".repeat(50));
    let json = match decript_file_to_json(&mc,&Path::new(DB_NAME)) {
        Ok(json) => Some(json),
        Err(_) => None
    };
    if json == None {
        wrong_pass();
    }
    let mut json = json.unwrap();
    for (num,k_v) in json.iter().enumerate() {
        println!("[{}] {}\n[>] {}",num,k_v.0.bright_green().underline(),k_v.1.bright_red())
    }
    println!("Digite a linha que você quer editar:");
    print!("> ");
    let ch1 = read_input();
    if ch1.parse::<usize>().is_ok() && ch1.parse::<usize>().as_ref().unwrap() <= &(&json.len()-1) {
        let lock = ch1.parse::<usize>().unwrap();
        println!("{}","=".repeat(50));
        println!("Selecionado:\n[{}] {}\n[>] {}",lock,json.iter().nth(lock).unwrap().0.bright_green(),json.iter().nth(lock).unwrap().1.bright_red());
        println!("Deseja:\n1 - Editar\n2 - Remover\n3 - Sair");
        print!("> ");
        let ch2 = read_input();
        println!("{}","=".repeat(50));
        if ch2 == "1" {
            println!("Digite o novo nome/user:");
            print!("> ");
            let title = read_input();
            stdout().flush().unwrap();
            let upw1 = password_twice("Digite a nova senha:");
            println!("Deseja salvar: [y/n]");
            print!("> ");
            let ch3 = read_input().to_lowercase();
            if ch3 != "y" {
                println!("Processo cancelado.");
                process::exit(0)
            }
            println!("{}","=".repeat(50));
            println!("{}","Editando...".bright_cyan());
            json.remove(&json.iter().nth(lock).unwrap().0.to_owned()).unwrap();
            json.insert(title, upw1);
            println!("{}","Encriptando...".bright_cyan());
            encript_json_to_file(&mc,Path::new(DB_NAME), json);
            println!("{}","Salvo com sucesso.".bright_green());
            process::exit(0);
        }else if ch2 == "2" {
            println!("Deseja remover: [y/n]");
            print!("> ");
            let ch3 = read_input();
            if ch3 != "y" {
                println!("Processo cancelado.");
                process::exit(0)
            }
            println!("{}","=".repeat(50));
            println!("{}","Removendo...".bright_cyan());
            json.remove(&json.iter().nth(lock).unwrap().0.to_owned()).unwrap();
            println!("{}","Encriptando...".bright_cyan());
            encript_json_to_file(&mc,Path::new(DB_NAME), json);
            println!("{}","Salvo com sucesso.".bright_green());
            process::exit(0);
        }else {
            println!("Saindo.");
            process::exit(0);
        }
    }else {
        println!("{}","Erro ao selecionar.".bright_red());
        process::exit(0)
    }
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
    //abilita suporte para ansi
    stdout()
    .execute(Clear(ClearType::All)).unwrap()
    .execute(MoveTo(0,0)).unwrap()
    .execute(SetTitle("Password Vault")).unwrap();
    windows_color::enable_ansi_support().expect("Falha ao setar cores para windows.");
    
    //check do --edit mode
    match env::args().nth(1) {
        Some(arg) => {
            if arg == "--edit" {
                edit_mode()
            }
        }
        None => {}
    }

    //se crypt.db não existir é criado
    if !Path::new(DB_NAME).exists() {
        File::create(DB_NAME).unwrap();
        println!("{}","Arquivo crypt.db criado.".bright_green())
    }
    //avisa para criar uma senha
    if File::open(Path::new(DB_NAME)).unwrap().metadata().unwrap().len() == 0 {
        println!("{}","================================= ATENÇÃO =================================".bright_red());
        println!("{}",format!("O arquivo {} está vazio.",DB_NAME).bright_red());
        println!("{}","Você deve salvar alguma senha antes de tentar acessar o banco de dados.".bright_red());
        println!("{}","A senha usada para acessar o banco de dados será a senha sua futura senha.".bright_red());
        println!("{}","===========================================================================".bright_red());
    }
    //inicio
    println!("{}","=".repeat(50));
    println!("{}","Bem Vindo ao Password Vault".bright_cyan());
    println!("{}","=".repeat(50));
    let sel_opts = vec!["Acessar o banco de dados","Adicionar uma senha customizada","Gerar uma senha"];
    let sel = Select::new("",sel_opts.to_owned()).with_help_message("↑↓ para mover, enter para selecionar").prompt().expect("Falha ao selecionar");
    println!("{}","=".repeat(50));

    if sel == sel_opts[0] {
        //acesso ao banco de dados
        println!("{}","Deseja".bright_cyan());
        println!("{}","=".repeat(50));
        let sel_opts = vec!["Mostrar no programa (Seguro)","Extrair para um .txt (Não seguro)"];
        let sel = Select::new("",sel_opts.to_owned()).with_help_message("↑↓ para mover, enter para selecionar").prompt().expect("Falha ao selecionar");
        println!("{}","=".repeat(50));
        let pw = Password::new("Digite a senha para o banco de dados:\n>").with_display_mode(PasswordDisplayMode::Masked).prompt().expect("Falha ao ler senha");
        println!("{}","=".repeat(50));
        let mc = new_magic_crypt!(pw,256);
        println!("{}","Decriptando...".bright_cyan());
        println!("{}","=".repeat(50));
        if sel == sel_opts[0] {
            show_on_terminal(&mc);
        }else if sel == sel_opts[1] {
            extract_to_txt(&mc)
        }
        println!("{}","=".repeat(50));
        println!("{}","Decriptado com sucesso.".bright_green());
        println!("{}","=".repeat(50));
    
    }else if sel == sel_opts[1] {
        //adiciona uma senha
        println!("Digite um nome/user para essa senha:");
        print!("> ");
        let title = read_input();
        stdout().flush().unwrap();
        let upw1 = password_twice("Digite a senha:");
        println!("{}","=".repeat(50));
        let pw = Password::new("Digite a senha para o banco de dados:\n>").with_display_mode(PasswordDisplayMode::Masked).prompt().expect("Falha ao ler senha");
        println!("{}","=".repeat(50));
        let mc = new_magic_crypt!(pw,256);
        save_password(&mc, title, upw1)

    }else if sel == sel_opts[2] {
        //gera uma senha
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
    //espera uma tecla ser apertada para sair
    println!("Aperte enter para sair.");
    stdout().flush().unwrap();
    stdin().read(&mut [0u8]).unwrap();
}