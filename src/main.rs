
extern crate ssh2;
extern crate clap;

use std::net::TcpStream;
use ssh2::Session;
use clap::{Arg, App};




fn main() {

    let matches = App::new("CVE-2018-10933 Scanner")
        .version("0.1.0")
        .author("Ivan Acosta-Rubio <ivan@softwarecriollo.com>")
        .about("CVE-2018-10933 Scanner. ")
        .arg(Arg::with_name("ip")
                 .required(true)
                 .takes_value(true)
                 .index(1)
                 .help("IP:port to scan for vulnerable libssh"))
        .get_matches();

    let server = matches.value_of("ip").unwrap();

    println!("{}", server);

    let tcp= TcpStream::connect(server).unwrap();

    let mut sess = Session::new().unwrap();
    sess.handshake(&tcp).unwrap();
    let banner = sess.banner().unwrap(); //read_to_string(&mut buffer);

    let split: Vec<_> = banner.split(".").collect();
    let version: i32 = split.last().clone().unwrap_or(&"9").parse().unwrap();


    println!("{}", banner);

    if banner.contains("libssh-0.6"){
        println!("Vulnerable")
    } else if banner.contains("libssh-0.7"){
        if version >= 6{
            println!("Not Vulnerable")
        }else{
            println!("Vulnerable")
        }
    } else if banner.contains("libssh-0.8"){
        if version >= 4 {
            println!("Not Vulnerable")
        }else{
            println!("Vulnerable")
        }
    }else{
        println!("Not Vulnerable");
    }
}
